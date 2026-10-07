"""WHOIS / RDAP module — Tier 1 (passive).

Looks up domain registration info via RDAP (Registration Data Access Protocol).
Falls back to WHOIS if RDAP unavailable.

MITRE ATT&CK: T1596.002 (WHOIS), T1590.001 (IP WHOIS)
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, ModuleInput, ModuleOutput


class WhoisRDAPModule(BaseReconModule):
    """WHOIS / RDAP domain registration intel.

    Public registration data only — does not query sensitive registrant info
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

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run WHOIS/RDAP lookup against the target domain.

        TODO(Day 2): Implement using `python-whois` or direct RDAP HTTP calls.
        Example RDAP endpoint: https://rdap.org/domain/{target}
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 2"],
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of WHOIS findings."""
        return """You are validating WHOIS/RDAP registration data for a target domain.

For each finding (registrar, dates, nameservers, registrant, statuses), classify as:
- CONFIRMED: data is consistent across sources and current
- LIKELY: data is plausible but possibly stale
- FALSE_POSITIVE: data appears wrong (e.g., placeholder, privacy-protected but mislabeled)
- SUSPECTED: data quality is uncertain

Prioritize findings by:
- HIGH: registrar history (frequent changes = suspicious), nameserver diversity
- MEDIUM: creation date, expiration date, status codes
- LOW: registrant info (often privacy-protected, low signal)

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "CONTINUE|PRODUCE_REPORT|REQUEST_USER_DECISION", "recommended_next_module_chain": [...]}"""


__all__ = ["WhoisRDAPModule"]
