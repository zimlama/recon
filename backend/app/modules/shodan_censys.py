"""Shodan / Censys module — Tier 2 (free tier, semi-passive).

Queries internet-wide asset search engines:
- Shodan InternetDB (https://internetdb.shodan.io/) — FREE, no key required
- Censys Search API (https://search.censys.io/api/v1/hosts) — FREE tier with API ID + Secret

Fully passive — never probes the target directly.

MITRE ATT&CK: T1596.005
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.config import get_settings
from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

# Shodan InternetDB — no auth required
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SHODAN_INTERNETDB_TIMEOUT = 15

# Censys Search API — requires API ID + Secret
CENSYS_SEARCH_URL = "https://search.censys.io/api/v1/hosts/{ip}"
CENSYS_TIMEOUT = 15
HTTP_TIMEOUT = 15


class ShodanCensysModule(BaseReconModule):
    """Internet-wide asset search (Shodan InternetDB + Censys)."""

    name = "shodan_censys"
    description = "Internet-wide asset search (Shodan InternetDB free + Censys free tier)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1596.005"]
    requires_api_keys: list[str] = []  # InternetDB is keyless; Censys optional
    requires_consent = False
    estimated_duration_seconds = 45
    enabled_by_default = False  # Tier 2 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query Shodan InternetDB + Censys for the target.

        Strategy:
        1. Resolve target domain to IPs (we already have dns_enum findings)
        2. Filter to IP range only (SSRF defense: no RFC 1918)
        3. Query Shodan InternetDB for each IP (free, no key)
        4. If Censys API keys are set, query Censys too (free tier)
        5. Convert each result to a finding
        """
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. Resolve domain → IPs
        ips = await self._resolve_to_ips(target)
        if not ips:
            errors.append(f"Could not resolve {target} to any IP")
            return ModuleOutput(
                module=self.name,
                findings=findings,
                duration_seconds=time.time() - start,
                errors=errors,
            )

        # 2. SSRF defense: only query public IPs
        from app.utils.network import filter_public_ips
        public_ips = filter_public_ips(ips)
        if not public_ips:
            errors.append(f"No public IPs found for {target} (all resolved IPs are private/reserved)")
            return ModuleOutput(
                module=self.name,
                findings=findings,
                duration_seconds=time.time() - start,
                errors=errors,
            )

        # 3. Query Shodan InternetDB for each public IP (SSRF defense: no RFC 1918)
        for ip in public_ips:
            try:
                shodan_data = await self._query_shodan_internetdb(ip)
                if shodan_data:
                    findings.extend(self._shodan_to_findings(ip, shodan_data))
            except Exception as e:  # noqa: BLE001
                errors.append(f"Shodan InternetDB query for {ip} failed: {e!s}")

        # 4. Query Censys if keys are set (also only public IPs)
        settings = get_settings()
        if settings.CENSYS_API_ID and settings.CENSYS_API_SECRET:
            for ip in public_ips:
                try:
                    censys_data = await self._query_censys(ip, settings.CENSYS_API_ID, settings.CENSYS_API_SECRET)
                    if censys_data:
                        findings.extend(self._censys_to_findings(ip, censys_data))
                except Exception as e:  # noqa: BLE001
                    errors.append(f"Censys query for {ip} failed: {e!s}")
        else:
            # Not an error — just inform
            logger.debug("censys_keys_not_set", module=self.name)

        # Dedupe
        unique = self._dedupe(findings)
        return ModuleOutput(
            module=self.name,
            findings=unique,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    # ---- AI prompt (used by /system/ AI validation) ----

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of Shodan/Censys findings."""
        return """You are validating Shodan/Censys findings for a target domain.

For each host/service/port/CVE finding, classify as:
- CONFIRMED: service is publicly accessible, banner matches
- LIKELY: service exists but banner may be obscured
- FALSE_POSITIVE: port is filtered, banner is generic, sinkholed IP
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_level: HIGH (admin panels, DBs, dev tools), MEDIUM (web servers, mail), LOW (CDN, static)
- cve_risk: any known CVEs from banner version
- priority: based on exposure + known vulnerabilities
- reasoning: 1 sentence

Watch for:
- Exposed databases (MongoDB, Redis, Elasticsearch without auth)
- Outdated software with known CVEs
- Default credentials
- C2 framework signatures (Cobalt Strike, Covenant, Sliver)
- Industrial control systems (if target shouldn't have them)
- Misconfigured cloud storage (S3 buckets open to public)

Respond with structured JSON matching the LDMValidationResult schema."""

    # ---- Private helpers ----

    async def _resolve_to_ips(self, domain: str) -> list[str]:
        """Resolve domain to IPs using DNS A records."""
        import dns.resolver

        try:
            answers = dns.resolver.resolve(domain, "A", raise_on_no_answer=False)
            return [str(rdata.address) for rdata in answers]
        except Exception:  # noqa: BLE001
            return []

    async def _query_shodan_internetdb(self, ip: str) -> dict[str, Any] | None:
        """Query Shodan InternetDB for an IP. Free, no key required.

        Returns: {"ip": "...", "ports": [...], "cpes": [...], "hostnames": [...], ...}
        """
        url = SHODAN_INTERNETDB_URL.format(ip=ip)
        try:
            async with httpx.AsyncClient(timeout=SHODAN_INTERNETDB_TIMEOUT) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    logger.debug("shodan_internetdb_non_200", status=response.status_code, ip=ip)
                    return None
                return response.json()
        except httpx.HTTPError as e:
            logger.debug("shodan_internetdb_http_error", error=str(e), ip=ip)
            return None

    async def _query_censys(
        self, ip: str, api_id: str, api_secret: str
    ) -> dict[str, Any] | None:
        """Query Censys Search API for an IP. Free tier with API ID + Secret."""
        url = CENSYS_SEARCH_URL.format(ip=ip)
        try:
            async with httpx.AsyncClient(timeout=CENSYS_TIMEOUT) as client:
                response = await client.get(url, auth=(api_id, api_secret))
                if response.status_code != 200:
                    logger.debug("censys_non_200", status=response.status_code, ip=ip)
                    return None
                return response.json()
        except httpx.HTTPError as e:
            logger.debug("censys_http_error", error=str(e), ip=ip)
            return None

    def _shodan_to_findings(self, ip: str, data: dict[str, Any]) -> list[Finding]:
        """Convert a Shodan InternetDB response to findings."""
        findings: list[Finding] = []

        # Ports
        for port in data.get("ports", []):
            findings.append(
                Finding(
                    type=FindingType.IP_ADDRESS,
                    value=f"{ip}:{port}",
                    source="shodan_internetdb",
                    confidence=0.95,
                    finding_metadata={
                        "ip": ip,
                        "port": port,
                        "hostnames": data.get("hostnames", []),
                        "cpes": data.get("cpes", []),
                        "tags": data.get("tags", []),
                    },
                )
            )

        # Hostnames
        for hostname in data.get("hostnames", []):
            findings.append(
                Finding(
                    type=FindingType.OTHER,
                    value=hostname,
                    source="shodan_internetdb",
                    confidence=0.9,
                    finding_metadata={"ip": ip, "kind": "hostname"},
                )
            )

        return findings

    def _censys_to_findings(self, ip: str, data: dict[str, Any]) -> list[Finding]:
        """Convert a Censys Search API response to findings."""
        findings: list[Finding] = []

        for service in data.get("services", []):
            port = service.get("port", "?")
            service_name = service.get("service_name", "unknown")
            findings.append(
                Finding(
                    type=FindingType.IP_ADDRESS,
                    value=f"{ip}:{port}",
                    source="censys",
                    confidence=0.95,
                    finding_metadata={
                        "ip": ip,
                        "port": port,
                        "service_name": service_name,
                        "transport_protocol": service.get("transport_protocol"),
                        "extended_service_name": service.get("extended_service_name"),
                    },
                )
            )

        return findings

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        """Dedupe by (value, source), preserving first-seen."""
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.value, f.source)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


__all__ = ["ShodanCensysModule"]
