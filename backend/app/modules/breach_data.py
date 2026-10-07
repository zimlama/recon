"""Breach data OSINT module — Tier 3 (white-hat gated).

Uses HIBP k-anonymity API to check if target emails appear in known breaches.
GATED: requires explicit user consent due to PII handling.

MITRE ATT&CK: T1589.001
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class BreachDataModule(BaseReconModule):
    """Breach data OSINT (HIBP k-anonymity)."""

    name = "breach_data"
    description = "Credential breach exposure via HIBP k-anonymity API (no plaintext ever)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1589.001"]
    requires_api_keys: list[str] = []  # HIBP_API_KEY optional
    requires_consent = True  # Tier 3 — explicit consent required
    estimated_duration_seconds = 20
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Check breach exposure for target emails.

        TODO(Day 6): Implement:
        - Take email list from email_harvesting module (or accept input)
        - HIBP k-anonymity: hash email, send first 5 chars, get suffix list
        - Cross-reference: are any of the suffixes a match?
        - Return: list of (email, breach_count) pairs
        - NEVER log or store plaintext emails — only the count
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 6"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating breach exposure findings for a target organization.

For each (email_hash_prefix, breach_count) pair, classify as:
- CONFIRMED: count is > 0, exposure is real
- LIKELY: count is high (>5), suggests credential reuse risk
- FALSE_POSITIVE: count is 0 or near-zero
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_risk: HIGH (>10 breaches), MEDIUM (1-10), LOW (0-1)
- reuse_likelihood: HIGH if password reuse is common, MEDIUM otherwise
- reasoning: 1 sentence

PRINCIPLE: NEVER recommend using found credentials to log in. Use only to
inform the user about password reuse risk. Authorized credential testing
must use a separate, consent-based workflow.

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["BreachDataModule"]
