"""Email harvesting module — Tier 1 (passive, PII-handling gated).

Collects public email addresses associated with the target domain from:
1. PGP public key servers (pgp.mit.edu) — most reliable
2. Email pattern inference from known usernames + common patterns
3. (Future) Hunter.io, theHarvester — opt-in via API key

This module requires consent (`requires_consent = True`) because it deals
with PII. All findings are logged locally only — never transmitted.

MITRE ATT&CK: T1589.002
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any

import httpx

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

# PGP key server endpoints (free, no auth)
PGP_KEYSERVERS = [
    "https://keys.openpgp.org",
    "https://pgp.mit.edu",
]

# Common email patterns to try based on domain
EMAIL_LOCAL_PARTS = [
    "admin",
    "administrator",
    "root",
    "postmaster",
    "hostmaster",
    "webmaster",
    "info",
    "support",
    "contact",
    "sales",
    "marketing",
    "press",
    "media",
    "noreply",
    "no-reply",
    "security",
    "abuse",
    "legal",
    "privacy",
    "compliance",
    "hr",
    "jobs",
    "careers",
    "billing",
    "accounts",
    "help",
    "hello",
    "team",
    "dev",
    "engineering",
    "tech",
    "it",
    "ops",
    "cto",
    "ceo",
    "cfo",
    "founder",
]

# Pattern to extract email addresses from arbitrary text
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Filter out obvious role-based / no-reply addresses (low signal for recon)
ROLE_BASED = {
    "admin", "administrator", "root", "postmaster", "hostmaster",
    "webmaster", "info", "support", "contact", "sales", "marketing",
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "security", "abuse", "legal", "privacy", "compliance",
    "hr", "jobs", "careers", "billing", "accounts", "help",
    "hello", "team", "dev", "engineering", "tech", "it", "ops",
    "noc", "www", "ftp", "mailer-daemon",
}

# Filter out obvious test / placeholder patterns
TEST_PATTERNS = re.compile(
    r"(test|fake|example|placeholder|noreply|donotreply|sample)", re.IGNORECASE
)

# Privacy filter: discard emails going to common anti-harvesting providers
PRIVACY_PROTECTED_DOMAINS = {
    "example.com", "example.org", "example.net",
    "yourdomain.com", "mydomain.com",
}

PGP_TIMEOUT = 30
HTTP_TIMEOUT = 15


class EmailHarvestingModule(BaseReconModule):
    """Public email harvesting (PGP keyservers + pattern inference).

    PII handling: requires explicit user consent. Only collects public emails.
    Never used for unauthorized outreach. Used for credential exposure analysis
    (which emails appear in known breaches) and username pattern discovery.
    """

    name = "email_harvesting"
    description = "Public email discovery (PGP keyservers + pattern inference)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1589.002"]
    requires_api_keys: list[str] = []  # Hunter.io optional future
    requires_consent = True  # PII handling
    estimated_duration_seconds = 90
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run email harvesting against the target domain."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. PGP key servers
        try:
            pgp_emails = await self._query_pgp_servers(target)
            for email in pgp_emails:
                findings.append(self._email_to_finding(email, "pgp_keyserver"))
        except Exception as e:  # noqa: BLE001
            errors.append(f"PGP keyserver query failed: {e!s}")

        # 2. Email pattern inference (generate candidates, don't actually verify)
        # We don't verify (that would be active), just record the candidate patterns
        # — AI validator decides which to actually probe in Phase 2
        for local_part in EMAIL_LOCAL_PARTS[:10]:  # top 10 most common
            candidate = f"{local_part}@{target}"
            findings.append(
                Finding(
                    type=FindingType.EMAIL,
                    value=candidate,
                    source="pattern_inference",
                    confidence=0.3,  # low — these are guesses
                    finding_metadata={
                        "verified": False,
                        "method": "common_pattern",
                    },
                )
            )

        # 3. Try theHarvester (if installed)
        harvester_findings = await self._run_theharvester(target)
        for email in harvester_findings:
            findings.append(self._email_to_finding(email, "theharvester"))

        # Dedupe + filter
        unique = self._dedupe_and_filter(findings)

        return ModuleOutput(
            module=self.name,
            findings=unique,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of email harvesting findings."""
        return """You are validating email harvesting findings for a target domain.

For each email address, classify as:
- CONFIRMED: real, active, deliverable (verified via SMTP or API)
- LIKELY: appears real but unverifiable (PGP key but no SMTP check)
- FALSE_POSITIVE: role-based (info@, noreply@), test addresses, obvious fakes, unrelated domain
- SUSPECTED: data quality uncertain, can't determine

Enrich each with:
- role_type: executive (CEO, CTO, founder), IT/security, engineering, generic, support, dev, marketing
- priority: HIGH (executive + IT — privileged targets), MEDIUM (engineering, dev), LOW (generic)
- breach_exposure: 0-1 (low), 2-5 (medium), 6+ (high)
- reasoning: 1 sentence

Watch for:
- Privacy-protected addresses (redacted but still useful as pattern)
- Pattern inference: firstname.lastname, flast, etc.
- Disposable/temporary email services
- Typosquatted look-alike domains in email addresses
- Auto-generated addresses (noreply@, no-reply@) — low signal

PII HANDLING: Only validate. Never suggest using these emails for unauthorized
outreach. Authorized phishing scope must be explicit and consent-based.

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    async def _query_pgp_servers(self, domain: str) -> set[str]:
        """Query PGP key servers for keys associated with the domain.

        Returns a set of email addresses found in PGP keys.
        """
        emails: set[str] = set()
        for server in PGP_KEYSERVERS:
            try:
                server_emails = await self._query_single_pgp_server(server, domain)
                emails.update(server_emails)
            except Exception as e:  # noqa: BLE001
                logger.debug(
                    "pgp_server_failed", server=server, error=str(e), domain=domain
                )
                continue
        return emails

    async def _query_single_pgp_server(
        self, server: str, domain: str
    ) -> set[str]:
        """Query a single PGP key server.

        Uses the HKP (HTTP Keyserver Protocol) index endpoint:
        GET /pks/lookup?search={domain}&op=index
        Returns text/plain with email addresses.
        """
        url = f"{server}/pks/lookup"
        params = {"search": domain, "op": "index"}
        try:
            async with httpx.AsyncClient(timeout=PGP_TIMEOUT) as client:
                response = await client.get(url, params=params)
                if response.status_code != 200:
                    return set()
                # Response is text/plain with one email per line
                text = response.text
        except httpx.HTTPError as e:
            logger.debug("pgp_http_error", server=server, error=str(e))
            return set()

        emails: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # HKP format: "uid\tName <email>\tcreated\t..."
            # Or sometimes just "email@example.com"
            for match in EMAIL_REGEX.finditer(line):
                email = match.group(0).lower()
                if email.endswith(f"@{domain.lower()}"):
                    emails.add(email)
        return emails

    async def _run_theharvester(self, domain: str) -> set[str]:
        """Run theHarvester if installed (subprocess)."""
        if not shutil.which("theHarvester"):
            return set()
        try:
            proc = await asyncio.create_subprocess_exec(
                "theHarvester",
                "-d", domain,
                "-b", "all",  # all sources
                "-f", "/tmp/theharvester_output",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, _stderr = await asyncio.wait_for(
                proc.communicate(), timeout=60
            )
        except (TimeoutError, OSError) as e:
            logger.debug("theharvester_failed", error=str(e))
            return set()

        # Parse the output file
        output_path = Path("/tmp/theharvester_output.xml")  # noqa: S108
        if not output_path.exists():
            return set()

        emails: set[str] = set()
        try:
            content = output_path.read_text(encoding="utf-8", errors="replace")
            for match in EMAIL_REGEX.finditer(content):
                email = match.group(0).lower()
                if email.endswith(f"@{domain.lower()}"):
                    emails.add(email)
        except Exception as e:  # noqa: BLE001
            logger.debug("theharvester_parse_failed", error=str(e))
        finally:
            try:
                output_path.unlink()
            except OSError:
                pass
        return emails

    def _email_to_finding(self, email: str, source: str) -> Finding:
        """Convert an email to a Finding with metadata."""
        local_part = email.split("@", 1)[0]
        return Finding(
            type=FindingType.EMAIL,
            value=email,
            source=source,
            confidence=0.85 if source == "pgp_keyserver" else 0.7,
            finding_metadata={
                "local_part": local_part,
                "verified": source in ("pgp_keyserver", "theharvester"),
                "is_role_based": local_part.lower() in ROLE_BASED,
            },
        )

    def _dedupe_and_filter(self, findings: list[Finding]) -> list[Finding]:
        """Dedupe by email + filter out test/role-based with low confidence."""
        by_value: dict[str, Finding] = {}
        for f in findings:
            value = f.value.lower()
            # Skip privacy-protected domains
            domain = value.split("@", 1)[-1] if "@" in value else ""
            if domain in PRIVACY_PROTECTED_DOMAINS:
                continue
            # Skip obvious test patterns
            if TEST_PATTERNS.search(value):
                continue
            # Dedupe (prefer higher confidence)
            if value not in by_value:
                by_value[value] = f
            elif f.confidence > by_value[value].confidence:
                by_value[value] = f
        return list(by_value.values())


__all__ = ["EmailHarvestingModule"]
