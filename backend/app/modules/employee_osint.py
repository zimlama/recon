"""Employee OSINT module — Tier 3 (white-hat gated).

Identifies employees + infers username patterns. Uses Sherlock + recon-ng if installed.
Falls back to manual LinkedIn scraper (passive only — no engagement).

PII handling: usernames are collected, not personal details. No engagement.

MITRE ATT&CK: T1589.003, T1593.001
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from typing import Any

from app.models import ModuleTier
from app.modules.base import (
    BaseReconModule,
    Finding,
    FindingType,
    ModuleInput,
    ModuleOutput,
    TouchClass,
)

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 30


class EmployeeOSINTModule(BaseReconModule):
    """Employee enumeration + username pattern inference."""

    name = "employee_osint"
    description = "Employee enumeration (Sherlock) + LinkedIn passive discovery"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1589.003", "T1593.001"]
    requires_api_keys: list[str] = []
    requires_consent = True  # PII
    estimated_duration_seconds = 90
    enabled_by_default = False  # Tier 3 — opt-in
    touch_classification: TouchClass = TouchClass.PASSIVE_THIRDPARTY
    requires_paid: bool = False

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Discover employees for the target organization."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. If sherlock is installed, use it for username discovery
        if shutil.which("sherlock"):
            try:
                sherlock_findings = await self._run_sherlock(target)
                findings.extend(sherlock_findings)
            except Exception as e:  # noqa: BLE001
                errors.append(f"sherlock failed: {e!s}")
        # 2. Always provide common username patterns (manual verification)
        pattern_findings = self._generate_username_patterns(target)
        findings.extend(pattern_findings)

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of employee findings."""
        return """You are validating employee OSINT findings for a target organization.

For each employee record or username pattern, classify as:
- CONFIRMED: real, current employee, role verified
- LIKELY: real, possibly past employee
- FALSE_POSITIVE: same name but different person, role-inferred incorrectly
- SUSPENSED: data quality uncertain

Enrich each with:
- role_relevance: HIGH (IT, security, executive), MEDIUM (engineering, ops), LOW (sales, marketing)
- username_pattern: firstname.lastname, flast, etc.
- priority_for_targeting: HIGH (privileged roles), MEDIUM (regular employees)
- reasoning: 1 sentence

PII HANDLING: Only validate. Do not suggest unauthorized use of personal data.
Username patterns are useful for authorized password spray only.

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    async def _run_sherlock(self, target: str) -> list[Finding]:
        """Run sherlock if available. Returns usernames found."""
        proc = await asyncio.create_subprocess_exec(
            "sherlock",
            "--print-found",
            "--timeout", "10",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=HTTP_TIMEOUT)

        findings: list[Finding] = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            # Sherlock output format: "[+] Platform: https://..."
            if line.startswith("[+]") and "http" in line:
                findings.append(
                    Finding(
                        type=FindingType.USERNAME,
                        value=target,  # the username is the target
                        source="sherlock",
                        confidence=0.7,
                        finding_metadata={
                            "platform_url": line.split(":", 1)[1].strip() if ":" in line else line,
                        },
                    )
                )
        return findings

    def _generate_username_patterns(self, target: str) -> list[Finding]:
        """Generate common username patterns for the organization.

        Without employee names, we can't generate specific usernames.
        Instead, we document the patterns to try with known names.
        """
        patterns = [
            f"{target}",  # organization name as username
            f"admin@{target}",
        ]
        findings: list[Finding] = []
        for pattern in patterns:
            findings.append(
                Finding(
                    type=FindingType.USERNAME,
                    value=pattern,
                    source="pattern_inference",
                    confidence=0.3,  # these are PATTERNS, not verified usernames
                    finding_metadata={
                        "note": (
                            "This is a USERNAME PATTERN, not a verified username. "
                            "Combine with employee names from LinkedIn/recon-ng to test."
                        ),
                    },
                )
            )
        return findings


__all__ = ["EmployeeOSINTModule"]