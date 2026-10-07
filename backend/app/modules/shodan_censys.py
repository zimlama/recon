"""Shodan / Censys module — Tier 2 (free tier, semi-passive).

Internet-wide asset search using Shodan InternetDB (free, no key) and
Censys (free tier with API credentials).

MITRE ATT&CK: T1596.005
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class ShodanCensysModule(BaseReconModule):
    """Shodan InternetDB + Censys cert search."""

    name = "shodan_censys"
    description = "Internet-wide asset search (Shodan InternetDB free, Censys free tier)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1596.005"]
    requires_api_keys: list[str] = []  # InternetDB is keyless
    estimated_duration_seconds = 45
    enabled_by_default = False  # Tier 2 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query Shodan InternetDB + Censys for the target.

        TODO(Day 3): Implement:
        - Shodan InternetDB: https://internetdb.shodan.io/{ip}
        - Censys hosts API: https://search.censys.io/api/v1/hosts/{ip}
        - Returns: open ports, services, banners, CVEs
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 3"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating Shodan/Censys findings for a target domain.

For each service/port/banner finding, classify as:
- CONFIRMED: service is publicly accessible, banner matches
- LIKELY: service exists but banner may be obscured
- FALSE_POSITIVE: port is filtered, banner is generic
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_level: HIGH (admin panels, DBs, dev tools), MEDIUM (web servers, mail), LOW (CDN, static)
- cve_risk: any known CVEs from banner version
- priority: based on exposure and known vulnerabilities
- reasoning: 1 sentence

Watch for:
- Exposed databases (MongoDB, Redis, Elasticsearch without auth)
- Outdated software with known CVEs
- Default credentials
- C2 framework signatures (Cobalt Strike, Covenant, Sliver)
- Industrial control systems (if target shouldn't have them)

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["ShodanCensysModule"]
