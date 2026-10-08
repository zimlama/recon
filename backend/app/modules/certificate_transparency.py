"""Certificate Transparency module — Tier 1 (passive).

Queries public Certificate Transparency (CT) logs via crt.sh (free HTTP API).
Extracts subdomains from Subject Alternative Names (SAN) in issued certificates.
Fully passive — never contacts the target.

This is a separate module from `subdomain_enum` (which also queries crt.sh)
because CT is its own distinct reconnaissance technique: it can reveal
subdomains that subfinder/crt.sh's general search miss, especially
historical subdomains from expired certificates.

MITRE ATT&CK: T1596.003
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.models import ModuleTier
from app.modules.base import (
    BaseReconModule,
    Finding,
    FindingType,
    ModuleInput,
    ModuleOutput,
    TouchClass,
)

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 45  # crt.sh can be slow
HTTP_TIMEOUT = 15
# crt.sh rate-limits aggressive scraping; be polite
CRTSH_BATCH_SIZE = 500  # max results per query


class CertificateTransparencyModule(BaseReconModule):
    """Certificate Transparency log mining (crt.sh)."""

    name = "certificate_transparency"
    description = "CT log mining via crt.sh (finds subdomains in issued certificates)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.003"]
    requires_api_keys: list[str] = []
    requires_consent = False
    estimated_duration_seconds = 30
    enabled_by_default = True
    touch_classification: TouchClass = TouchClass.PASSIVE_THIRDPARTY
    requires_paid: bool = False

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query crt.sh for certificates issued to the target domain."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        try:
            crtsh_data = await self._query_crtsh(target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"crt.sh query failed: {e!s}")
            return ModuleOutput(
                module=self.name,
                findings=findings,
                duration_seconds=time.time() - start,
                errors=errors,
            )

        if crtsh_data is None:
            errors.append("crt.sh returned no data")
            return ModuleOutput(
                module=self.name,
                findings=findings,
                duration_seconds=time.time() - start,
                errors=errors,
            )

        if not crtsh_data:
            # Empty list is a valid response (no certs found), not an error
            return ModuleOutput(
                module=self.name,
                findings=findings,
                duration_seconds=time.time() - start,
                errors=errors,
            )

        # Process each certificate entry
        for entry in crtsh_data:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value", "")
            if not name_value:
                continue

            # crt.sh may return multiple names in one entry, newline-separated
            for raw_name in name_value.split("\n"):
                name = self._normalize_name(raw_name, target)
                if not name:
                    continue
                findings.append(
                    Finding(
                        type=FindingType.SUBDOMAIN,
                        value=name,
                        source="crt.sh",
                        confidence=0.95,
                        finding_metadata={
                            "issuer": entry.get("issuer_name"),
                            "issuer_dn": entry.get("issuer_dn"),
                            "common_name": entry.get("common_name"),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                            "serial_number": entry.get("serial_number"),
                            "cert_id": entry.get("id"),
                            "matching_identifiers": entry.get("matching_identifiers"),
                        },
                    )
                )

        # Dedupe (preserve first-seen metadata per value)
        unique = self._dedupe(findings)
        return ModuleOutput(
            module=self.name,
            findings=unique,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of CT findings."""
        return """You are validating Certificate Transparency findings for a target domain.

For each certificate (CN, SAN, issuer, validity period), classify as:
- CONFIRMED: cert is currently valid, CA is trusted
- LIKELY: cert is valid but CA is unusual
- FALSE_POSITIVE: cert is expired, revoked, or for unrelated domain
- SUSPECTED: data quality uncertain

Enrich each with:
- subdomain_priority: HIGH (newly issued admin/vpn/dev), MEDIUM (production), LOW (test/staging)
- risk_signals: e.g., self-signed, expired recently, unusual CA
- reasoning: 1 sentence

Watch for:
- Internal hostnames in SANs (leaked internal naming — high signal)
- Typosquatted look-alikes (e.g., examp1e.com near example.com)
- Recently expired certs (might be replaced with weaker alternative)
- Free CAs (Let's Encrypt) vs paid (more legitimate usually)
- Multiple certs for same domain = key rotation (informational)
- Certs with unusually long validity (10+ years) = suspicious
- Wildcard certs (*.example.com) — note but don't filter

Respond with structured JSON matching the LDMValidationResult schema."""

    # ---- Private helpers ----

    async def _query_crtsh(self, domain: str) -> list[dict[str, Any]] | None:
        """Query crt.sh for certificates matching the domain.

        crt.sh API: GET /?q={domain}&output=json
        Returns a JSON array of certificate entries.
        """
        params = {
            "q": f"%.{domain}",  # % is wildcard in crt.sh
            "output": "json",
        }
        try:
            async with httpx.AsyncClient(timeout=CRTSH_TIMEOUT) as client:
                response = await client.get(CRTSH_URL, params=params)
                if response.status_code != 200:
                    logger.debug(
                        "crtsh_non_200", status=response.status_code, domain=domain
                    )
                    return None
                try:
                    return response.json()
                except Exception as e:  # noqa: BLE001
                    logger.debug("crtsh_invalid_json", error=str(e))
                    return None
        except httpx.HTTPError as e:
            logger.debug("crtsh_http_error", error=str(e), domain=domain)
            return None

    def _normalize_name(self, raw_name: str, target: str) -> str | None:
        """Normalize a name from crt.sh and filter to target domain.

        Returns the cleaned name if it matches the target, None otherwise.
        """
        name = raw_name.strip().lstrip("*.").lower()
        if not name:
            return None
        # Must end with the target domain (with a dot boundary, so "notexample.com"
        # doesn't match "example.com")
        target_lower = target.lower()
        if name.endswith("." + target_lower):
            pass
        elif name == target_lower:
            # Bare target = filtered (not a subdomain)
            return None
        else:
            return None
        # Must contain at least one dot (real subdomain)
        if "." not in name:
            return None
        return name

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        """Dedupe by value, preserving the first-seen (likely most complete) entry."""
        by_value: dict[str, Finding] = {}
        for f in findings:
            if f.value not in by_value:
                by_value[f.value] = f
            # Prefer higher confidence
            elif f.confidence > by_value[f.value].confidence:
                by_value[f.value] = f
        return list(by_value.values())


__all__ = ["CertificateTransparencyModule"]
