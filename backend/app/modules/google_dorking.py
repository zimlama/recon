"""Google Dorking module — Tier 2 (semi-passive).

Search-engine advanced operators to find exposed files, admin panels, etc.
Uses SerpAPI (optional, requires SERP_API_KEY) or returns curated GHDB-style
dork templates that the user can run manually.

MITRE ATT&CK: T1593.002
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.config import get_settings
from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

SERPAPI_URL = "https://serpapi.com/search"
SERPAPI_TIMEOUT = 15

# Curated dork templates (GHDB-style) — these are query strings to run
# against Google. Useful when SERP_API_KEY is not set.
DORK_TEMPLATES = [
    'site:{target} filetype:env',
    'site:{target} filetype:sql',
    'site:{target} filetype:bak',
    'site:{target} inurl:admin',
    'site:{target} inurl:login',
    'site:{target} inurl:config',
    'site:{target} intitle:"index of"',
    'site:{target} ext:xml | ext:json | ext:yaml',
    'site:{target} "password" | "api_key" | "secret"',
    'site:{target} "DB_USERNAME" | "DB_PASSWORD"',
    'site:{target} "BEGIN RSA PRIVATE KEY"',
    'site:{target} "wp-config.php"',
    'site:{target} ".env"',
    'site:{target} inurl:phpmyadmin',
    'site:{target} inurl:jenkins',
    'site:{target} inurl:grafana',
    'site:{target} inurl:kibana',
    'site:{target} inurl:swagger',
    'site:{target} inurl:"/api/v1"',
    'site:{target} "API documentation"',
]

# Default file types of interest
INTERESTING_FILE_TYPES = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "sql", "env", "bak", "old", "config", "xml", "json", "yaml", "yml",
    "log", "csv", "txt", "md",
}


class GoogleDorkingModule(BaseReconModule):
    """Google Dorking — search-engine recon for exposed files/panels.

    Requires SERP_API_KEY for actual Google searches. Without it, the module
    returns the curated dork templates so the user can run them manually.
    """

    name = "google_dorking"
    description = "Google dorking via SerpAPI (optional) + curated GHDB-style templates"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1593.002"]
    requires_api_keys: list[str] = []  # SERP_API_KEY optional
    requires_consent = False
    estimated_duration_seconds = 60
    enabled_by_default = False  # Tier 2 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run Google dork queries for the target."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. Always provide the dork templates (so the user can run them)
        template_findings = self._build_template_findings(target)
        findings.extend(template_findings)

        # 2. If SerpAPI key is set, run actual searches
        settings = get_settings()
        if settings.SERP_API_KEY:
            try:
                serp_findings = await self._search_serpapi(target, settings.SERP_API_KEY)
                findings.extend(serp_findings)
            except Exception as e:  # noqa: BLE001
                errors.append(f"SerpAPI search failed: {e!s}")
        else:
            logger.debug("serpapi_key_not_set", module=self.name)

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of Google Dorking findings."""
        return """You are validating Google Dorking findings for a target domain.

For each URL/content found, classify as:
- CONFIRMED: real, accessible, in scope
- LIKELY: real but may be auth-walled
- FALSE_POSITIVE: 404, parked, redirect, captcha
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_type: admin_panel, exposed_file, backup, login, config, error_page
- severity: CRITICAL (exposed config, secrets), HIGH (admin panel), MEDIUM (login, error), LOW (marketing)
- reasoning: 1 sentence why

Watch for:
- Exposed .env files (contain credentials)
- SQL dumps (data breach)
- Backup files (.bak, .old)
- Admin panels (unauth access)
- API keys in code
- Error pages leaking stack traces / server info
- Webcam / IoT device interfaces

Respond with structured JSON matching the LDMValidationResult schema."""

    # ---- Private helpers ----

    def _build_template_findings(self, target: str) -> list[Finding]:
        """Build a list of dork template findings (for manual execution)."""
        findings: list[Finding] = []
        for template in DORK_TEMPLATES:
            dork = template.format(target=target)
            findings.append(
                Finding(
                    type=FindingType.URL_HISTORICAL,
                    value=dork,
                    source="google_dork_template",
                    confidence=1.0,  # the template is valid
                    finding_metadata={
                        "dork": dork,
                        "target": target,
                        "category": self._categorize_dork(dork),
                        "requires": "manual execution OR SERP_API_KEY",
                    },
                )
            )
        return findings

    def _categorize_dork(self, dork: str) -> str:
        """Categorize a dork by what it's looking for.

        Order matters: check the most specific file types first
        (env → credentials, sql/bak → backup) before generic patterns.
        """
        dork_lower = dork.lower()

        # Most specific: env files (credentials) and db backups
        if "env" in dork_lower and ("filetype" in dork_lower or "ext:" in dork_lower):
            return "credentials"
        if "password" in dork_lower or "api_key" in dork_lower or "secret" in dork_lower:
            return "credentials"
        if "rsa" in dork_lower or "private" in dork_lower:
            return "credentials"

        if any(x in dork_lower for x in ("sql", "bak", "backup", ".old", "dump")):
            return "backup"

        # Admin panels
        if any(x in dork_lower for x in ("admin", "login", "phpmyadmin", "jenkins", "grafana", "kibana")):
            return "admin_panel"

        # Config files (xml, json, yaml)
        if any(x in dork_lower for x in ("config", "xml", "json", "yaml", "wp-config")):
            return "config"

        # Generic filetype/ext (e.g., pdf, doc, xls) without specific keywords
        if "filetype" in dork_lower or "ext:" in dork_lower:
            return "exposed_file"

        return "other"

    async def _search_serpapi(self, target: str, api_key: str) -> list[Finding]:
        """Run dork queries via SerpAPI and collect results."""
        findings: list[Finding] = []
        # Pick a subset of the most useful dorks
        priority_dorks = [
            f"site:{target} filetype:env",
            f"site:{target} inurl:admin",
            f"site:{target} inurl:login",
            f"site:{target} filetype:sql",
            f"site:{target} filetype:bak",
            f"site:{target} ext:xml OR ext:json OR ext:yaml",
            f"site:{target} inurl:phpmyadmin",
            f"site:{target} inurl:jenkins OR inurl:grafana",
        ]

        for dork in priority_dorks:
            try:
                results = await self._serpapi_query(dork, api_key)
                for r in results:
                    url = r.get("link", "")
                    title = r.get("title", "")
                    snippet = r.get("snippet", "")
                    if not url:
                        continue
                    findings.append(
                        Finding(
                            type=FindingType.URL_HISTORICAL,
                            value=url,
                            source="serpapi",
                            confidence=0.85,
                            finding_metadata={
                                "dork": dork,
                                "title": title,
                                "snippet": snippet,
                            },
                        )
                    )
            except Exception:  # noqa: BLE001
                continue  # continue with next dork
        return findings

    async def _serpapi_query(self, query: str, api_key: str) -> list[dict[str, Any]]:
        """Run a single SerpAPI Google query."""
        params = {
            "q": query,
            "api_key": api_key,
            "engine": "google",
            "num": 10,  # 10 results per query
        }
        try:
            async with httpx.AsyncClient(timeout=SERPAPI_TIMEOUT) as client:
                response = await client.get(SERPAPI_URL, params=params)
                if response.status_code != 200:
                    return []
                data = response.json()
        except httpx.HTTPError:
            return []
        return data.get("organic_results", [])


__all__ = ["GoogleDorkingModule"]
