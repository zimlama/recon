"""Dark web OSINT module — Tier 3 (white-hat gated, requires Tor sidecar).

Monitors Tor hidden services for credential dumps, target mentions, actor tradecraft.
GATED: requires explicit user consent + Tor network access in lab-isolated env.

MITRE ATT&CK: T1589.001, T1593.001
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class DarkWebOSINTModule(BaseReconModule):
    """Dark web OSINT (Tor hidden services)."""

    name = "dark_web_osint"
    description = "Dark web monitoring (Tor, ahmia, Telegram/Discord channels)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1589.001", "T1593.001"]
    requires_api_keys: list[str] = []
    requires_consent = True  # Tier 3 — explicit consent required
    estimated_duration_seconds = 180
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleInput:  # type: ignore[override]
        """Run dark web monitoring.

        TODO(Day 6): Implement:
        - Tor sidecar required (separate Docker container with tor + torsocks)
        - ahmia.fi search API (clearnet, indexes .onion)
        - Telegram/Discord channel monitoring (requires API tokens)
        - Read-only, evidence-archived

        SECURITY: This module REQUIRES a lab-isolated environment. Do NOT
        run on a production workstation. Container must have no internet
        access except via Tor.
        """
        return ModuleOutput(  # type: ignore[return-value]
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 6"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating dark web OSINT findings for a target organization.

For each mention/credential dump, classify as:
- CONFIRMED: real, current, active listing
- LIKELY: real but possibly outdated
- FALSE_POSITIVE: paste site, unrelated, hoax
- SUSPECTED: data quality uncertain

Enrich each with:
- source_type: market, paste, forum, telegram, discord
- severity: CRITICAL (live credentials), HIGH (employee PII), MEDIUM (mention), LOW (historical)
- safety_considerations: do NOT interact with threat actors
- reasoning: 1 sentence

SAFETY RULES:
- Read-only, no transactions
- Do NOT engage with threat actors
- Document all access for chain of custody
- Never tip off the target during active recon

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["DarkWebOSINTModule"]
