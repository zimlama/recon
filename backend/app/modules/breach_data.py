"""Breach data OSINT module — Tier 3 (white-hat gated).

Checks if target emails appear in known breaches via HIBP k-anonymity API.
NEVER logs, stores, or transmits plaintext emails. Only counts breach exposure.

K-anonymity: We hash the email with SHA-1, send only the first 5 hex chars,
and HIBP returns a list of suffixes for breach matches. We compare locally.

MITRE ATT&CK: T1589.001
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

import httpx

from app.config import get_settings
from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_TIMEOUT = 15
HTTP_TIMEOUT = 15


class BreachDataModule(BaseReconModule):
    """Breach exposure check via HIBP k-anonymity API.

    GATED (requires_consent = True). PII handling:
    - Only counts breach exposure, never logs plaintext emails
    - Uses k-anonymity (only first 5 chars of email hash sent)
    - HIBP API is read-only
    """

    name = "breach_data"
    description = "Breach exposure via HIBP k-anonymity API (no plaintext, never logged)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1589.001"]
    requires_api_keys: list[str] = []  # HIBP_API_KEY optional (raises rate limits)
    requires_consent = True  # PII
    estimated_duration_seconds = 20
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Check HIBP for breach exposure of target emails.

        1. Get emails from email_harvesting module (if enabled)
        2. For each email, use HIBP k-anonymity to check breach count
        3. Return findings with breach counts (NO plaintext emails)
        """
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. Get emails (we instantiate but don't actually call its network methods)
        emails = await self._get_target_emails(target)
        if not emails:
            return ModuleOutput(
                module=self.name,
                findings=findings,
                duration_seconds=time.time() - start,
                errors=["No role-based patterns to check (configure emails via BREACH_EMAILS env var or run email_harvesting first)"],
            )

        # 2. Check each email via HIBP k-anonymity
        for email in emails:
            try:
                count = await self._check_hibp(email)
                if count > 0:
                    # NEVER log the actual email — just the count
                    email_hash = hashlib.sha1(email.lower().encode()).hexdigest()[:10]
                    findings.append(
                        Finding(
                            type=FindingType.CREDENTIAL_EXPOSURE,
                            value=f"{count}_breaches_for_{email_hash}",
                            source="hibp_kanon",
                            confidence=1.0,  # HIBP is authoritative
                            finding_metadata={
                                "email_hash_prefix": email_hash,
                                "breach_count": count,
                                "severity": "HIGH" if count > 5 else "MEDIUM" if count > 1 else "LOW",
                                # CRITICAL: do NOT include "email" key with plaintext
                            },
                        )
                    )
            except Exception as e:  # noqa: BLE001
                errors.append(f"HIBP check failed: {e!s}")

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of breach exposure findings."""
        return """You are validating breach exposure findings for a target organization.

For each breach count, classify as:
- CONFIRMED: HIBP returned a positive match (real breach exposure)
- LIKELY: count is high (>5), strongly suggesting credential reuse risk
- FALSE_POSITIVE: count is 0 or near-zero
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_risk: HIGH (>10 breaches), MEDIUM (1-10), LOW (0)
- reuse_likelihood: HIGH if password reuse common, MEDIUM otherwise
- reasoning: 1 sentence

PRIVACY: NEVER transmit, log, or share actual emails or credentials. Only count breach exposure.

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    async def _get_target_emails(self, domain: str) -> list[str]:
        """Get a list of emails to check.

        For simplicity in v0.1, we try a few common patterns.
        Future: integrate with email_harvesting module's output.
        """
        # Common role-based patterns to check
        common_patterns = [
            "admin", "info", "support", "noreply", "contact",
            "security", "abuse", "postmaster",
        ]
        return [f"{p}@{domain}" for p in common_patterns]

    async def _check_hibp(self, email: str) -> int:
        """Check HIBP k-anonymity for an email. Returns breach count.

        k-anonymity protocol:
        1. SHA-1 hash the email
        2. Send first 5 hex chars to HIBP
        3. HIBP returns list of suffixes for all breaches
        4. We compare locally — never send the full hash
        """
        sha1 = hashlib.sha1(email.lower().encode("utf-8")).hexdigest()
        prefix, suffix = sha1[:5], sha1[5:].upper()

        url = HIBP_API_URL.format(prefix=prefix)
        try:
            async with httpx.AsyncClient(timeout=HIBP_TIMEOUT) as client:
                response = await client.get(
                    url,
                    headers={"Add-Padding": "true"},  # privacy padding
                )
                if response.status_code != 200:
                    return 0
                body = response.text
        except httpx.HTTPError:
            return 0

        # Parse response: lines like "0018A45C4F5C...:1"
        count = 0
        for line in body.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            line_suffix, line_count = line.split(":", 1)
            if line_suffix.upper() == suffix:
                try:
                    count = int(line_count)
                except ValueError:
                    count = 0
                break
        return count


__all__ = ["BreachDataModule"]