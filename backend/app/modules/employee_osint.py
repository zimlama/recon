"""Employee OSINT module — Tier 3 (white-hat gated).

Identifies employees and infers username conventions for password spray.

MITRE ATT&CK: T1589.003, T1593.001
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class EmployeeOSINTModule(BaseReconModule):
    """Employee identification + username inference."""

    name = "employee_osint"
    description = "Employee enumeration (LinkedIn, sherlock) + username pattern inference"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1589.003", "T1593.001"]
    requires_api_keys: list[str] = []
    requires_consent = True  # Tier 3 — explicit consent required
    estimated_duration_seconds = 90
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Enumerate employees + infer username patterns.

        TODO(Day 6): Implement:
        - LinkedIn2Username (if LinkedIn API access)
        - Sherlock for username enumeration across platforms
        - recon-ng (passive modules)
        - Cross-reference: same name on multiple platforms = real person
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 6"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating employee OSINT findings for a target organization.

For each employee record, classify as:
- CONFIRMED: real, current employee, role verified
- LIKELY: real, possibly past employee
- FALSE_POSITIVE: same name but different person, role-inferred incorrectly
- SUSPECTED: data quality uncertain

Enrich each with:
- role_relevance: HIGH (IT, security, executive), MEDIUM (engineering, ops), LOW (sales, marketing)
- username_pattern: firstname.lastname, flast, etc.
- priority_for_targeting: HIGH (privileged roles), MEDIUM (regular employees)
- reasoning: 1 sentence

PII HANDLING: Only validate. Do not suggest unauthorized use of personal
data. Username patterns are useful for authorized password spray only.

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["EmployeeOSINTModule"]
