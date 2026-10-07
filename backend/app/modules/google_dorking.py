"""Google Dorking module — Tier 2 (passive).

Search-engine advanced operators to find exposed files, admin panels, etc.

MITRE ATT&CK: T1593.002
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class GoogleDorkingModule(BaseReconModule):
    """Google Dorking (search-engine advanced operators)."""

    name = "google_dorking"
    description = "Google dorking via SerpAPI (optional) or manual GHDB queries"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1593.002"]
    requires_api_keys: list[str] = []  # SERP_API_KEY optional
    estimated_duration_seconds = 60
    enabled_by_default = False  # Tier 2 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run Google dorking queries.

        TODO(Day 3): Implement:
        - SerpAPI search with dork queries (if SERP_API_KEY set)
        - Otherwise: provide manual dork templates + GHDB seed
        - Dorks: site:, filetype:, inurl:, intitle:, ext:, cache:
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 3"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating Google Dorking findings for a target domain.

For each URL/content found, classify as:
- CONFIRMED: real, accessible, in scope
- LIKELY: real but may be auth-walled
- FALSE_POSITIVE: 404, parked, redirect, captcha
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_type: admin_panel, exposed_file, backup, login, config, error_page
- severity: CRITICAL (exposed config, secrets), HIGH (admin panel), MEDIUM (login, error), LOW (marketing)
- reasoning: 1 sentence

Common high-value dorks:
- site:target.com filetype:env | filetype:sql | filetype:bak
- site:target.com inurl:admin | inurl:login | inurl:config
- site:target.com ext:xml | ext:json | ext:yaml
- site:target.com "password" | "api_key"

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["GoogleDorkingModule"]
