"""Subdomain enumeration module — Tier 1 (passive).

Combines subfinder (Go binary, if installed) with crt.sh (free HTTP API).
Deduplicates results. No active DNS brute force (requires explicit user opt-in).

MITRE ATT&CK: T1596.002, T1596.003, T1589.001
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
SUBFINDER_TIMEOUT = 90  # seconds (subfinder can be slow for big domains)
CRTSH_TIMEOUT = 30
HTTP_TIMEOUT = 15


class SubdomainEnumModule(BaseReconModule):
    """Subdomain enumeration (passive only).

    Sources:
    - subfinder (Go binary, if installed) — enumerates via many passive sources
    - crt.sh (free HTTP API) — certificate transparency logs

    Active DNS brute force is NOT included by default (would require explicit
    consent + wordlist).
    """

    name = "subdomain_enum"
    description = "Subdomain discovery via subfinder + crt.sh (passive, no DNS brute force)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.002", "T1596.003", "T1589.001"]
    requires_api_keys: list[str] = []
    requires_consent = False
    estimated_duration_seconds = 120
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run subdomain enumeration against the target."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()
        sources_used: list[str] = []

        # 1. subfinder (if installed)
        subfinder_findings = await self._run_subfinder(target)
        if subfinder_findings is not None:
            findings.extend(subfinder_findings)
            sources_used.append("subfinder")
        else:
            errors.append("subfinder not installed or failed (non-fatal)")

        # 2. crt.sh (always available)
        crtsh_findings = await self._query_crtsh(target)
        if crtsh_findings:
            findings.extend(crtsh_findings)
            sources_used.append("crt.sh")
        else:
            errors.append("crt.sh query failed")

        # 3. Dedupe (preserve first-seen source for each subdomain)
        unique = self._dedupe(findings, target)

        return ModuleOutput(
            module=self.name,
            findings=unique,
            duration_seconds=time.time() - start,
            errors=errors,
            raw_output_path=None,  # could write JSON dump of unique subdomains
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of subdomain findings."""
        return """You are validating subdomain enumeration results for a target domain.

For each subdomain, classify as:
- CONFIRMED: resolves to a live IP, real, in scope
- LIKELY: resolves but possibly stale (parked domain, sinkhole)
- FALSE_POSITIVE: typo, wildcard catch-all, out of scope, sub-subdomain (e.g., foo.bar.example.com is fine, but *.foo.example.com is a wildcard)
- SUSPECTED: data quality uncertain

Enrich each with:
- tech_stack_hint: observed from passive sources
- priority_for_next_phase: HIGH (admin, staging, api, internal, vpn), MEDIUM (www, app, blog), LOW (parked, redirects)
- reasoning: 1 sentence why

Watch for:
- Internal hostnames that leaked via cert transparency
- Typosquatted look-alikes (e.g., examp1e.com, exanple.com)
- Wildcard DNS (entire *.example.com returns same IP — usually a CDN)
- Stale subdomains that no longer resolve

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    async def _run_subfinder(self, domain: str) -> list[Finding] | None:
        """Run subfinder if available. Returns findings or None if not installed."""
        # Check if subfinder is in PATH
        import shutil

        if not shutil.which("subfinder"):
            logger.debug("subfinder_not_in_path")
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder",
                "-d",
                domain,
                "-silent",
                "-json",
                "-timeout",
                "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=SUBFINDER_TIMEOUT)
        except (TimeoutError, OSError) as e:
            logger.debug("subfinder_failed", error=str(e))
            return None

        findings: list[Finding] = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host")
                if host and isinstance(host, str):
                    findings.append(
                        Finding(
                            type=FindingType.SUBDOMAIN,
                            value=host.lower().strip(),
                            source="subfinder",
                            confidence=0.9,
                            finding_metadata={
                                "input": data.get("input"),
                                "source": data.get("source"),
                            },
                        )
                    )
            except json.JSONDecodeError:
                continue
        return findings

    async def _query_crtsh(self, domain: str) -> list[Finding]:
        """Query crt.sh for certificates issued to this domain."""
        url = CRTSH_URL.format(domain=domain)
        try:
            async with httpx.AsyncClient(timeout=CRTSH_TIMEOUT) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    logger.debug("crtsh_non_200", status=response.status_code)
                    return []
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    logger.debug("crtsh_invalid_json")
                    return []
        except httpx.HTTPError as e:
            logger.debug("crtsh_http_error", error=str(e))
            return []

        findings: list[Finding] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value", "")
            if not name_value:
                continue

            # crt.sh may return multiple names in one entry, newline-separated
            for raw_name in name_value.split("\n"):
                name = raw_name.strip().lstrip("*.").lower()
                if not name or not name.endswith(domain):
                    continue
                findings.append(
                    Finding(
                        type=FindingType.SUBDOMAIN,
                        value=name,
                        source="crt.sh",
                        confidence=0.95,
                        finding_metadata={
                            "issuer": entry.get("issuer_name"),
                            "issuer_cn": entry.get("issuer_dn"),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                            "serial_number": entry.get("serial_number"),
                            "cert_id": entry.get("id"),
                        },
                    )
                )
        return findings

    def _dedupe(self, findings: list[Finding], target: str) -> list[Finding]:
        """Dedupe by subdomain value, preserving the first-seen source per value.

        Priority: subfinder (more metadata) > crt.sh (very high confidence).
        """
        by_value: dict[str, Finding] = {}
        for f in findings:
            value = f.value.lower().strip()
            if not value or not value.endswith(target):
                continue
            if value not in by_value:
                by_value[value] = f
            else:
                # Prefer the higher-confidence source
                if f.confidence > by_value[value].confidence:
                    by_value[value] = f
        return list(by_value.values())


__all__ = ["SubdomainEnumModule"]
