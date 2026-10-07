"""WHOIS / RDAP module — Tier 1 (passive).

Looks up domain registration info via RDAP (Registration Data Access Protocol),
falling back to WHOIS via subprocess if RDAP is unavailable. RDAP is preferred
because it returns structured JSON; WHOIS is parsed heuristically.

MITRE ATT&CK: T1596.002 (WHOIS), T1590.001 (IP WHOIS)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)


# RDAP bootstrap endpoint
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"

# Common WHOIS field patterns (for fallback parsing)
_WHOIS_PATTERNS: dict[str, re.Pattern[str]] = {
    "registrar": re.compile(r"Registrar:\s*(.+?)(?:\r?\n|$)", re.IGNORECASE),
    "creation_date": re.compile(r"(?:Creation Date|Created On|Registered On):\s*(.+?)(?:\r?\n|$)", re.IGNORECASE),
    "expiration_date": re.compile(r"(?:Registry Expiry Date|Expiration Date|Expires On):\s*(.+?)(?:\r?\n|$)", re.IGNORECASE),
    "updated_date": re.compile(r"(?:Updated Date|Last Modified):\s*(.+?)(?:\r?\n|$)", re.IGNORECASE),
    "registrant": re.compile(r"Registrant(?: Organization)?:\s*(.+?)(?:\r?\n|$)", re.IGNORECASE),
    "nameservers_raw": re.compile(r"(?:Name Server|Nameservers?):\s*(.+?)(?:\r?\n|$)", re.IGNORECASE),
    "status": re.compile(r"(?:Domain Status|Status):\s*(.+?)(?:\r?\n|$)", re.IGNORECASE),
    "emails": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
}


class WhoisRDAPModule(BaseReconModule):
    """WHOIS / RDAP domain registration intel.

    Public registration data only. Does not query sensitive registrant info
    beyond what is publicly available via RDAP.
    """

    name = "whois_rdap"
    description = "Domain registration intel via RDAP (preferred) and WHOIS (fallback)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.002", "T1590.001"]
    requires_api_keys: list[str] = []
    requires_consent = False
    estimated_duration_seconds = 10
    enabled_by_default = True

    # ---- Public API ----

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run WHOIS/RDAP lookup against the target domain.

        Strategy:
        1. Try RDAP first (structured JSON, no parsing).
        2. Fall back to WHOIS via subprocess (parsed heuristically).
        3. Combine both into a single "registration record" finding.
        """
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. RDAP
        rdap_data: dict[str, Any] | None = None
        try:
            rdap_data = await self._query_rdap(target)
        except Exception as e:  # noqa: BLE001
            errors.append(f"RDAP query failed: {e!s}")

        # 2. WHOIS fallback (if RDAP failed or returned empty)
        whois_text: str | None = None
        if not rdap_data:
            try:
                whois_text = await self._query_whois(target)
            except Exception as e:  # noqa: BLE001
                errors.append(f"WHOIS query failed: {e!s}")

        # 3. Build findings
        if rdap_data:
            findings.extend(self._extract_from_rdap(rdap_data, target))
        elif whois_text:
            findings.extend(self._extract_from_whois(whois_text, target))
        else:
            errors.append("Both RDAP and WHOIS returned no data")

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of WHOIS findings."""
        return """You are validating WHOIS/RDAP registration data for a target domain.

For each finding (registrar, dates, nameservers, registrant, statuses), classify as:
- CONFIRMED: data is consistent across sources and current
- LIKELY: data is plausible but possibly stale
- FALSE_POSITIVE: data appears wrong (e.g., placeholder, privacy-protected but mislabeled)
- SUSPECTED: data quality uncertain

Prioritize findings by:
- HIGH: registrar history (frequent changes = suspicious), nameserver diversity
- MEDIUM: creation date, expiration date, status codes
- LOW: registrant info (often privacy-protected, low signal)

Watch for: very recent creation (potential phishing setup), privacy redaction, nameservers in unexpected jurisdictions.

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    async def _query_rdap(self, domain: str) -> dict[str, Any] | None:
        """Query RDAP for the domain. Returns parsed JSON or None on failure.

        SSRF defense: routes through ``BaseReconModule.safe_http_get_async``
        which enforces ``follow_redirects=False`` and swallows httpx errors.
        """
        url = RDAP_BOOTSTRAP_URL.format(domain=domain)
        # SSRF defense: safe_http_get_async (follow_redirects=False, swallows HTTPError)
        response = await self.safe_http_get_async(
            url,
            timeout=10.0,
            headers={"Accept": "application/rdap+json"},
        )
        if response is None:
            logger.debug("rdap_no_response", domain=domain)
            return None
        if response.status_code == 200:
            try:
                return response.json()
            except (ValueError, TypeError) as e:
                logger.debug("rdap_json_decode_error", error=str(e), domain=domain)
                return None
        logger.debug("rdap_non_200", status=response.status_code, domain=domain)
        return None

    async def _query_whois(self, domain: str) -> str | None:
        """Run whois via subprocess. Returns raw text or None on failure."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            text = stdout.decode("utf-8", errors="replace")
            return text if text.strip() else None
        except (TimeoutError, OSError) as e:
            logger.debug("whois_error", error=str(e), domain=domain)
            return None

    def _extract_from_rdap(
        self,
        data: dict[str, Any],
        domain: str,
    ) -> list[Finding]:
        """Build findings from a parsed RDAP response.

        RDAP response shape (RFC 7483):
        {
          "objectClassName": "domain",
          "handle": "...",
          "ldhName": "example.com",
          "status": ["active", "clientTransferProhibited"],
          "events": [
            {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"}
          ],
          "entities": [
            {"roles": ["registrar"], "vcardArray": [["vcard", [["fn", {}, "text", "Registrar Name"]]]]}
          ],
          "nameservers": [{"ldhName": "ns1.example.com"}]
        }
        """
        findings: list[Finding] = []
        metadata: dict[str, Any] = {
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "events": {},
            "entities": {},
            "nameservers": [],
        }

        # Extract events
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action and date:
                metadata["events"][action] = date

        # Extract entities (registrar, registrant, admin, tech)
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            # Extract name from vcard
            vcard = entity.get("vcardArray", [])
            name = self._extract_vcard_name(vcard)
            for role in roles:
                metadata["entities"][role] = name

        # Extract nameservers
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName")
            if ns_name:
                metadata["nameservers"].append(ns_name)

        # One consolidated "registration record" finding
        findings.append(
            Finding(
                type=FindingType.OTHER,
                value=domain,
                source="rdap",
                confidence=0.95,
                finding_metadata=metadata,
            )
        )

        # Individual nameserver findings
        for ns in metadata["nameservers"]:
            findings.append(
                Finding(
                    type=FindingType.OTHER,
                    value=ns,
                    source="rdap",
                    confidence=0.95,
                    finding_metadata={"role": "nameserver", "domain": domain},
                )
            )

        return findings

    def _extract_from_whois(self, text: str, domain: str) -> list[Finding]:
        """Build findings from parsed WHOIS text (heuristic)."""
        findings: list[Finding] = []
        metadata: dict[str, Any] = {}

        for field, pattern in _WHOIS_PATTERNS.items():
            if field == "emails":
                continue  # handled separately
            if field == "nameservers_raw":
                continue  # handled separately
            match = pattern.search(text)
            if match:
                value = match.group(1).strip()
                metadata[field] = value

        # Extract emails
        emails = set(_WHOIS_PATTERNS["emails"].findall(text))
        # Filter out privacy/service emails
        real_emails = {
            e for e in emails
            if not any(p in e.lower() for p in ["abuse", "privacy", "redact", "proxy", "whoisguard"])
        }
        metadata["emails"] = list(real_emails)

        # Extract nameservers — multiple "Name Server:" lines may be present
        nameservers: list[str] = []
        ns_pattern = re.compile(
            r"(?:Name Server|Nameservers?):\s*(\S+)",
            re.IGNORECASE,
        )
        for match in ns_pattern.finditer(text):
            ns = match.group(1).strip().lower().rstrip(".")
            if ns and "." in ns and not ns.startswith("http"):
                nameservers.append(ns)
        # Also try the single-line pattern (in case all on one line)
        if not nameservers:
            ns_match = _WHOIS_PATTERNS["nameservers_raw"].search(text)
            if ns_match:
                ns_text = ns_match.group(1)
                for token in ns_text.replace("\n", " ").split():
                    token = token.strip().lower().rstrip(".")
                    if token and "." in token and not token.startswith("http"):
                        nameservers.append(token)
        # Dedup while preserving order
        seen: set[str] = set()
        unique_ns: list[str] = []
        for ns in nameservers:
            if ns not in seen:
                seen.add(ns)
                unique_ns.append(ns)
        metadata["nameservers"] = unique_ns

        # Source confidence is lower for WHOIS (heuristic parsing)
        source = "whois"
        confidence = 0.7

        # Consolidated finding
        findings.append(
            Finding(
                type=FindingType.OTHER,
                value=domain,
                source=source,
                confidence=confidence,
                finding_metadata=metadata,
            )
        )

        # Individual nameserver findings
        for ns in nameservers:
            findings.append(
                Finding(
                    type=FindingType.OTHER,
                    value=ns,
                    source=source,
                    confidence=confidence * 0.9,
                    finding_metadata={"role": "nameserver", "domain": domain},
                )
            )

        return findings

    def _extract_vcard_name(self, vcard: list) -> str | None:
        """Extract the FN field from a vCard array.

        vCard format (RFC 7095):
        vcardArray: ["vcard", [["fn", {}, "text", "Registrar Name"], ...]]
        """
        if not vcard or len(vcard) < 2 or vcard[0] != "vcard":
            return None
        for field in vcard[1]:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                return str(field[3])
        return None


__all__ = ["WhoisRDAPModule"]
