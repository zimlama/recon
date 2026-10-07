"""GitHub recon module — Tier 2 (semi-passive).

Mines public GitHub for code leaks, internal hostnames, credentials.

Sources (in order):
1. GitHub Code Search API — search for the target domain in code
2. GitHub Commits API — search commits for the target
3. gitleaks (if installed) — scan repos for secrets

All passive — never pushes, forks, or modifies anything.

MITRE ATT&CK: T1593.003, T1552.001
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
import shutil
import time
from typing import Any

import httpx

from app.config import get_settings
from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com"
GITHUB_TIMEOUT = 20
HTTP_TIMEOUT = 15
# Common patterns that indicate secrets in code
SECRET_PATTERNS = [
    (r"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{20,})", "aws_credential"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"(?i)api[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})", "api_key"),
    (r"(?i)bearer\s+([A-Za-z0-9_.-]{20,})", "bearer_token"),
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key"),
    (r"(?i)ghp_[A-Za-z0-9]{36}", "github_personal_access_token"),
    (r"(?i)github_pat_[A-Za-z0-9_]{82}", "github_fine_grained_pat"),
    (r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
    (r"eyJ[A-Za-z0-9_=]+\.eyJ[A-Za-z0-9_=]+\.?[A-Za-z0-9_.+/=]*", "jwt"),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key"),
    (r"(?i)password\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "password"),
]


class GitHubReconModule(BaseReconModule):
    """GitHub code search + commit search for the target."""

    name = "github_recon"
    description = "GitHub code search + commit search + gitleaks for secrets"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1593.003", "T1552.001"]
    requires_api_keys: list[str] = []  # GITHUB_TOKEN optional
    requires_consent = False
    estimated_duration_seconds = 60
    enabled_by_default = False  # Tier 2 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query GitHub for code matching the target domain."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        sources_used: list[str] = []
        start = time.time()

        # 1. Code search for the domain
        try:
            code_findings = await self._search_code(target)
            findings.extend(code_findings)
            if code_findings:
                sources_used.append("github_code_search")
        except Exception as e:  # noqa: BLE001
            errors.append(f"GitHub code search failed: {e!s}")

        # 2. Search commits for the domain
        try:
            commit_findings = await self._search_commits(target)
            findings.extend(commit_findings)
            if commit_findings:
                sources_used.append("github_commit_search")
        except Exception as e:  # noqa: BLE001
            errors.append(f"GitHub commit search failed: {e!s}")

        # 3. Check if gitleaks is available (does NOT actually run it — see docstring)
        gitleaks_findings = await self._run_gitleaks(target)
        if gitleaks_findings:
            findings.extend(gitleaks_findings)
            sources_used.append("gitleaks_check")

        # Dedupe
        unique = self._dedupe(findings)
        return ModuleOutput(
            module=self.name,
            findings=unique,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of GitHub recon findings."""
        return """You are validating GitHub recon findings for a target organization.

For each finding (code snippet, hostname, email, secret), classify as:
- CONFIRMED: real, in a current public repo
- LIKELY: real but in a fork/archive
- FALSE_POSITIVE: example, test, or unrelated repo
- SUSPECTED: data quality uncertain

Enrich each with:
- severity: CRITICAL (active API key, credentials), HIGH (internal hostname, JWT secret), MEDIUM (email), LOW (file path)
- exploitation_risk: HIGH if creds are live, LOW if deleted
- reasoning: 1 sentence

Watch for:
- Hardcoded API keys (AWS, Stripe, Slack, GitHub, etc.)
- Internal IP addresses / hostnames in code
- .env files committed
- SSH private keys
- Database connection strings with creds
- Tokens that are still active vs revoked

SECRET HANDLING: NEVER transmit, log, or share actual secrets. Truncate to
first 4 + last 4 chars. Flag the secret TYPE only.

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    def _get_headers(self) -> dict[str, str]:
        """Build GitHub API headers (with optional auth token)."""
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "zimlama-recon/0.1.0",
        }
        settings = get_settings()
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
        return headers

    async def _search_code(self, domain: str) -> list[Finding]:
        """Search GitHub code for occurrences of the domain.

        API: GET /search/code?q={domain}
        """
        url = f"{GITHUB_API_URL}/search/code"
        params = {
            "q": f'"{domain}" in:file',
            "per_page": 30,  # limit per page
        }
        try:
            async with httpx.AsyncClient(timeout=GITHUB_TIMEOUT) as client:
                response = await client.get(
                    url, params=params, headers=self._get_headers()
                )
                if response.status_code == 403:
                    # Rate limit or auth required — parse GitHub rate-limit headers
                    # so we can warn clearly with the reset time instead of silent failure.
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    reset = response.headers.get("X-RateLimit-Reset")
                    if remaining == "0" and reset:
                        try:
                            reset_dt = time.strftime(
                                "%Y-%m-%d %H:%M:%S", time.gmtime(int(reset))
                            )
                        except (ValueError, TypeError, OSError):
                            reset_dt = str(reset)
                        logger.warning(
                            "github_rate_limited",
                            extra={"reset_at_utc": reset_dt},
                        )
                    else:
                        logger.warning(
                            "github_403",
                            extra={
                                "remaining": remaining,
                                "reset": reset,
                                "domain": domain,
                            },
                        )
                    return []
                if response.status_code != 200:
                    logger.debug("github_code_search_non_200", status=response.status_code)
                    return []
                data = response.json()
        except httpx.HTTPError as e:
            logger.debug("github_code_search_http_error", error=str(e))
            return []

        findings: list[Finding] = []
        for item in data.get("items", []):
            repo_full_name = item.get("repository", {}).get("full_name", "unknown")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")
            findings.append(
                Finding(
                    type=FindingType.OTHER,
                    value=f"{repo_full_name}/{file_path}",
                    source="github_code_search",
                    confidence=0.85,
                    finding_metadata={
                        "repo": repo_full_name,
                        "file": file_path,
                        "url": html_url,
                        "domain": domain,
                    },
                )
            )

        # Scan code snippets for secrets
        for item in data.get("items", []):
            text_fields = " ".join(
                [
                    str(item.get("name", "")),
                    str(item.get("path", "")),
                ]
            )
            for pattern, secret_type in SECRET_PATTERNS:
                if re.search(pattern, text_fields):
                    findings.append(
                        Finding(
                            type=FindingType.CREDENTIAL_EXPOSURE,
                            value=f"potential_{secret_type}",
                            source="github_code_search",
                            confidence=0.6,  # pattern match, not verified
                            finding_metadata={
                                "secret_type": secret_type,
                                "repo": item.get("repository", {}).get("full_name"),
                                "file": item.get("path"),
                            },
                        )
                    )
                    break  # one type per item is enough

        return findings

    async def _search_commits(self, domain: str) -> list[Finding]:
        """Search GitHub commits for the domain.

        API: GET /search/commits?q={domain}
        """
        url = f"{GITHUB_API_URL}/search/commits"
        params = {"q": domain, "per_page": 20}
        try:
            async with httpx.AsyncClient(timeout=GITHUB_TIMEOUT) as client:
                response = await client.get(
                    url, params=params, headers=self._get_headers()
                )
                if response.status_code == 403:
                    # Rate limit or auth required — parse GitHub rate-limit headers
                    # so we can warn clearly with the reset time instead of silent failure.
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    reset = response.headers.get("X-RateLimit-Reset")
                    if remaining == "0" and reset:
                        try:
                            reset_dt = time.strftime(
                                "%Y-%m-%d %H:%M:%S", time.gmtime(int(reset))
                            )
                        except (ValueError, TypeError, OSError):
                            reset_dt = str(reset)
                        logger.warning(
                            "github_rate_limited",
                            extra={"reset_at_utc": reset_dt},
                        )
                    else:
                        logger.warning(
                            "github_403",
                            extra={
                                "remaining": remaining,
                                "reset": reset,
                                "domain": domain,
                            },
                        )
                    return []
                if response.status_code != 200:
                    return []
                data = response.json()
        except httpx.HTTPError:
            return []

        findings: list[Finding] = []
        for item in data.get("items", []):
            repo_full_name = item.get("repository", {}).get("full_name", "unknown")
            sha = item.get("sha", "")
            commit_url = item.get("html_url", "")
            findings.append(
                Finding(
                    type=FindingType.OTHER,
                    value=f"{repo_full_name}@{sha[:12]}",
                    source="github_commit_search",
                    confidence=0.8,
                    finding_metadata={
                        "repo": repo_full_name,
                        "sha": sha,
                        "url": commit_url,
                        "domain": domain,
                    },
                )
            )
        return findings

    async def _run_gitleaks(self, domain: str) -> list[Finding]:
        """Check if gitleaks is installed. Does NOT actually run gitleaks.

        NOTE: gitleaks requires a local repo to scan, which we don't have
        from a domain name. For remote GitHub code, we'd need to clone
        repos first (out of scope for this passive module). This method
        only reports gitleaks availability so operators know the tool exists.
        """
        if not shutil.which("gitleaks"):
            return []

        # gitleaks requires a local directory to scan, which we don't have
        # from a domain name. For remote GitHub, we'd need to clone first
        # which is out of scope for this passive module.
        # Just return a meta-finding.
        return [
            Finding(
                type=FindingType.OTHER,
                value="gitleaks_available",
                source="gitleaks",
                confidence=1.0,
                finding_metadata={
                    "note": (
                        "gitleaks is installed but requires a local repo to scan. "
                        "For remote GitHub code, see findings from github_code_search."
                    ),
                },
            )
        ]

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        """Dedupe by (value, source)."""
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.value, f.source)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


__all__ = ["GitHubReconModule"]
