"""SOCMINT module — Tier 3 (white-hat gated).

Social media intelligence using passive techniques + authorized research personas.
Discovers public profiles on LinkedIn, GitHub, Twitter/X, etc.

GATED: respects platform ToS, no active engagement (no following, DM, liking).
PII handling: profiles are aggregated, not deep-scraped.

MITRE ATT&CK: T1593.001
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import shutil
import time
from typing import Any

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

SOCIAL_PLATFORMS = [
    # (platform_name, url_template, requires_auth)
    ("linkedin", "https://www.linkedin.com/company/{target}", False),
    ("github_org", "https://github.com/{target}", False),
    ("twitter", "https://twitter.com/{target}", False),
    ("facebook", "https://www.facebook.com/{target}", False),
    ("instagram", "https://www.instagram.com/{target}", False),
    ("youtube", "https://www.youtube.com/@{target}", False),
    ("tiktok", "https://www.tiktok.com/@{target}", False),
]

HTTP_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (compatible; zimlama-recon/0.1.0; +https://github.com/zimlama/recon)"


class SOCMINTModule(BaseReconModule):
    """Social Media Intelligence — passive profile discovery."""

    name = "socmint"
    description = "Social media profile discovery (LinkedIn, GitHub, Twitter/X, etc.)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1593.001"]
    requires_api_keys: list[str] = []  # Future: add API keys for richer data
    requires_consent = True  # PII handling required
    estimated_duration_seconds = 120
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Discover social media profiles for the target."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # Check each platform
        tasks = [
            self._check_platform(platform_name, url_template, target)
            for platform_name, url_template, _ in SOCIAL_PLATFORMS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (platform_name, url_template, _), result in zip(SOCIAL_PLATFORMS, results):
            if isinstance(result, Exception):
                errors.append(f"{platform_name} check failed: {result!s}")
                continue
            if result is None or not isinstance(result, str):
                continue  # platform not found or mock returned non-string
            findings.append(
                Finding(
                    type=FindingType.SOCIAL_PROFILE,
                    value=result,
                    source=f"socmint_{platform_name}",
                    confidence=0.7,  # existence check, not full profile
                    finding_metadata={
                        "platform": platform_name,
                        "url_template": url_template,
                    },
                )
            )

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of SOCMINT findings."""
        return """You are validating SOCMINT (Social Media Intelligence) findings for a target.

For each social profile, classify as:
- CONFIRMED: real, active, relevant to engagement
- LIKELY: real but possibly outdated
- FALSE_POSITIVE: sock puppet, unrelated person, fake
- SUSPECTED: data quality uncertain (note: NOT "SUSPENSED")

Enrich each with:
- platform: linkedin, github, twitter, etc.
- relevance: HIGH (employee, exec, IT), MEDIUM (vendor, partner), LOW (random mention)
- privacy_considerations: PII risk
- reasoning: 1 sentence

ETHICS:
- No active engagement (don't follow, like, DM)
- No doxxing individuals
- Respect platform ToS
- Note OPSEC risks: posting patterns reveal location/timezone

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    async def _check_platform(
        self, platform_name: str, url_template: str, target: str
    ) -> str | None:
        """Check if a social profile exists for the target on this platform.

        Returns the URL if found, None if not (404 etc.).
        Uses a HEAD-equivalent GET first (less intrusive), then a GET retry if
        the first attempt is blocked (405/403).

        SSRF defense: routes through ``BaseReconModule.safe_http_get_async``
        which enforces ``follow_redirects=False`` and swallows httpx errors.
        Operator must use authorized targets.
        """
        url = url_template.format(target=target)
        headers = {"User-Agent": USER_AGENT}
        try:
            # SSRF defense: safe_http_get_async (follow_redirects=False, swallows HTTPError)
            response = await self.safe_http_get_async(url, timeout=HTTP_TIMEOUT, headers=headers)
            if response is not None and response.status_code == 200:
                return url
            # Fall back to GET for sites that don't support HEAD-equivalent checks
            if response is not None and response.status_code in (405, 403):
                response = await self.safe_http_get_async(
                    url, timeout=HTTP_TIMEOUT, headers=headers
                )
                if response is not None and response.status_code == 200:
                    return url
            return None
        except (ValueError, TypeError) as e:
            logger.debug("socmint_http_error", platform=platform_name, error=str(e))
            return None


__all__ = ["SOCMINTModule"]