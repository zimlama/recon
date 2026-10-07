"""Email harvesting module — Tier 1 (passive).

Collects public emails from web pages, PGP keys, search engines, breach data.

MITRE ATT&CK: T1589.002 (Email Addresses)
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class EmailHarvestingModule(BaseReconModule):
    """Public email address discovery."""

    name = "email_harvesting"
    description = "Public email harvesting (theHarvester, Hunter.io, HIBP, PGP keys)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1589.002"]
    requires_api_keys: list[str] = []  # Hunter.io optional
    requires_consent = True  # PII handling required
    estimated_duration_seconds = 90
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Harvest public email addresses.

        TODO(Day 2): Implement combining:
        - theHarvester (optional binary)
        - Hunter.io API (if HUNTER_API_KEY set)
        - Google dorking for @target emails
        - PGP key servers
        - GitHub commit history (covered by github_recon module)

        IMPORTANT: PII handling — log only, never transmit, never use found
        emails for unauthorized outreach.
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 2"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating email harvesting findings for a target domain.

For each email address, classify as:
- CONFIRMED: real, active, deliverable (verified via SMTP or API)
- LIKELY: appears real but unverifiable
- FALSE_POSITIVE: role-based (info@, noreply@), test addresses, obvious fakes
- SUSPECTED: data quality uncertain

Enrich each with:
- role_type: executive, IT/security, generic, support, dev
- priority_for_targeting: HIGH (executive accounts often have higher access), LOW (generic)
- breach_exposure: if known from HIBP, note
- reasoning: 1 sentence

Watch for:
- Privacy-protected addresses (redacted but still useful as pattern)
- Pattern inference: firstname.lastname, flast, etc.
- Disposable/temporary email services
- Typosquatted look-alike domains in email addresses

PII HANDLING: Only validate. Never suggest using these emails for unauthorized
outreach. Authorized phishing scope must be explicit.

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["EmailHarvestingModule"]
