"""SOCMINT module — Tier 3 (white-hat gated).

Social-media intelligence using passive techniques + authorized research personas.

MITRE ATT&CK: T1593.001
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class SOCMINTModule(BaseReconModule):
    """Social Media Intelligence (passive)."""

    name = "socmint"
    description = "SOCMINT via Maltego, SpiderFoot (passive, no engagement)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1593.001"]
    requires_api_keys: list[str] = []
    requires_consent = True  # Tier 3 — explicit consent required
    estimated_duration_seconds = 120
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run passive SOCMINT.

        TODO(Day 6): Implement:
        - SpiderFoot HX (if available) or manual recon-ng
        - Target: organization name, key employees
        - Platforms: LinkedIn, Twitter/X, GitHub, Instagram, Facebook
        - Per-platform operators and metadata extraction
        - NO active engagement (no following, no DM, no liking)
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 6"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating SOCMINT findings for a target organization.

For each profile/connection/post, classify as:
- CONFIRMED: real, active, relevant to engagement
- LIKELY: real but possibly outdated
- FALSE_POSITIVE: sock puppet, unrelated person, fake
- SUSPECTED: data quality uncertain

Enrich each with:
- platform: linkedin, twitter, github, etc.
- relevance: HIGH (employee, exec, IT), MEDIUM (vendor, partner), LOW (random mention)
- privacy_considerations: PII risk
- reasoning: 1 sentence

ETHICS:
- No active engagement (don't follow, like, DM)
- No doxxing individuals
- Note OPSEC risks: posting patterns reveal location/timezone
- Respect platform ToS

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["SOCMINTModule"]
