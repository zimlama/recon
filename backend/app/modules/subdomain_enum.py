"""Subdomain enumeration module — Tier 1 (passive + active).

Combines passive sources (crt.sh, subfinder, amass) with active DNS bruteforce.

MITRE ATT&CK: T1596.002, T1596.003, T1589.001
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class SubdomainEnumModule(BaseReconModule):
    """Subdomain enumeration (passive + active)."""

    name = "subdomain_enum"
    description = "Subdomain discovery via subfinder, crt.sh, amass (passive) + DNS bruteforce (active)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.002", "T1596.003", "T1589.001"]
    requires_api_keys: list[str] = []
    estimated_duration_seconds = 120
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run subdomain enumeration.

        TODO(Day 2): Implement combining:
        - subfinder -d {target} -silent -json
        - crt.sh JSON API: https://crt.sh/?q={target}&output=json
        - amass enum -passive -d {target}
        - DNS bruteforce with wordlist (active, requires user consent)
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 2"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating subdomain enumeration results for a target domain.

For each subdomain, classify as:
- CONFIRMED: resolves to a live IP, real, in scope
- LIKELY: resolves but possibly stale (parked domain, sinkhole)
- FALSE_POSITIVE: typo, wildcard catch-all, out of scope
- SUSPECTED: data quality uncertain

Enrich each with:
- tech_stack_hint: observed from passive sources
- priority_for_next_phase: HIGH (admin/staging/api), MEDIUM (www/marketing), LOW (parked/redirects)
- reasoning: 1 sentence why

HIGH priority targets: admin, dev, staging, api, internal, vpn, cdn, mail
MEDIUM: www, app, blog, docs
LOW: cdn, static, marketing, blog (subdomains often duplicated)

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["SubdomainEnumModule"]
