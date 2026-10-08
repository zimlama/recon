"""Wayback Machine module — Tier 1 (passive).

Mines the Internet Archive (archive.org) Wayback Machine for historical URLs.
Uses the CDX API as primary source (no auth required, free) and gau/waybackurls
as supplementary tools if installed.

Fully passive — never contacts the target directly.

MITRE ATT&CK: T1593
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import shutil
import time
from typing import Any

import httpx

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

# CDX API endpoint (Internet Archive)
CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
CDX_TIMEOUT = 60  # CDX can be slow
HTTP_TIMEOUT = 20

# Path patterns worth flagging (interesting = worth re-checking)
INTERESTING_PATH_PATTERNS = [
    "/admin",
    "/administrator",
    "/login",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/pma",
    "/dbadmin",
    "/console",
    "/jenkins",
    "/gitlab",
    "/grafana",
    "/kibana",
    "/prometheus",
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/internal",
    "/private",
    "/staging",
    "/dev",
    "/test",
    "/backup",
    "/backups",
    "/dump",
    "/db",
    "/old",
    "/new",
    "/beta",
    "/.git",
    "/.env",
    "/.svn",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/config",
    "/conf",
    "/admin.php",
    "/wp-config",
    "/crossdomain.xml",
    "/.well-known",
    "/debug",
    "/trace",
    "/actuator",
    "/swagger",
    "/api-docs",
]


class WaybackMachineModule(BaseReconModule):
    """Wayback Machine historical URL enumeration.

    Sources (in order):
    1. gau (Get All URLs) — Go binary if installed
    2. waybackurls — Go binary if installed
    3. CDX API (Internet Archive) — always available, free
    """

    name = "wayback_machine"
    description = "Historical URL extraction (gau + waybackurls + Wayback CDX API)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1593"]
    requires_api_keys: list[str] = []
    requires_consent = False
    estimated_duration_seconds = 60
    enabled_by_default = True
    touch_classification: TouchClass = TouchClass.PASSIVE_THIRDPARTY
    requires_paid: bool = False

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query Wayback Machine for historical URLs."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        sources_used: list[str] = []
        start = time.time()

        # 1. Try gau (if installed)
        gau_findings = await self._run_tool("gau", target)
        if gau_findings is not None:
            findings.extend(gau_findings)
            sources_used.append("gau")
        # 2. Try waybackurls (if installed)
        wburls_findings = await self._run_tool("waybackurls", target)
        if wburls_findings is not None:
            findings.extend(wburls_findings)
            sources_used.append("waybackurls")
        # 3. CDX API (always available)
        cdx_findings = await self._query_cdx(target)
        if cdx_findings:
            findings.extend(cdx_findings)
            sources_used.append("cdx")
        else:
            if not sources_used:
                errors.append("All sources (gau, waybackurls, CDX) returned no data")

        # Dedupe
        unique = self._dedupe(findings)
        return ModuleOutput(
            module=self.name,
            findings=unique,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of Wayback findings."""
        return """You are validating Wayback Machine findings (historical URLs) for a target.

For each URL, classify as:
- CONFIRMED: URL was archived, content is still relevant
- LIKELY: URL exists in archive but content may be stale
- FALSE_POSITIVE: 404, parked, redirect, junk, non-target-domain
- SUSPECTED: data quality uncertain

Enrich each with:
- interesting_paths: /admin, /api, /dev, /staging, /internal, /backup, /.git, /.env
- priority: HIGH (sensitive paths or auth endpoints), MEDIUM (API endpoints), LOW (marketing/blog/static)
- reasoning: 1 sentence why

Watch for:
- Forgotten admin panels (often with default creds)
- Old API endpoints with weaker auth (might still respond)
- Backup files in URLs (.bak, .sql, .tar.gz, .zip)
- Development URLs that leaked to production
- Removed-but-still-referenced pages (links break but content archived)
- Test/QA environments (often less hardened)
- Internal documentation (employee handbooks, runbooks, credentials)
- Old CMS / blog / forum software (known CVEs)

PII / OPSEC: Archive.org is a third party. Do not include or exfiltrate credentials,
PII, or other sensitive data. Use only to identify attack surface for authorized testing.

Respond with structured JSON matching the LDMValidationResult schema."""

    # ---- Private helpers ----

    async def _run_tool(
        self, tool: str, domain: str
    ) -> list[Finding] | None:
        """Run a Go tool (gau or waybackurls) via subprocess.

        Returns the list of Finding, or None if the tool is not installed / fails.
        """
        if not shutil.which(tool):
            logger.debug("tool_not_in_path", tool=tool)
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                tool,
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(
                proc.communicate(), timeout=CDX_TIMEOUT
            )
        except (TimeoutError, OSError) as e:
            logger.debug("tool_failed", tool=tool, error=str(e))
            return None

        findings: list[Finding] = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            findings.append(self._url_to_finding(line, tool))
        return findings

    async def _query_cdx(self, domain: str) -> list[Finding]:
        """Query the Wayback Machine CDX API for archived URLs.

        CDX API: https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey
        """
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey",  # dedupe similar URLs
            "limit": "10000",  # safety limit
        }
        try:
            async with httpx.AsyncClient(timeout=CDX_TIMEOUT) as client:
                response = await client.get(CDX_API_URL, params=params)
                if response.status_code != 200:
                    logger.debug("cdx_non_200", status=response.status_code)
                    return []
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    return []
        except httpx.HTTPError as e:
            logger.debug("cdx_http_error", error=str(e))
            return []

        findings: list[Finding] = []
        if not data or len(data) < 2:
            return findings
        # First row is header
        header = data[0]
        try:
            url_idx = header.index("original")
            ts_idx = header.index("timestamp")
            status_idx = header.index("statuscode") if "statuscode" in header else None
            mime_idx = header.index("mimetype") if "mimetype" in header else None
        except ValueError:
            return findings

        for row in data[1:]:
            if not row or len(row) <= url_idx:
                continue
            url = row[url_idx]
            timestamp = row[ts_idx] if len(row) > ts_idx else None
            status_code = row[status_idx] if status_idx is not None and len(row) > status_idx else None
            mimetype = row[mime_idx] if mime_idx is not None and len(row) > mime_idx else None

            finding = self._url_to_finding(
                url,
                "wayback_cdx",
                timestamp=timestamp,
                status_code=status_code,
                mimetype=mimetype,
            )
            findings.append(finding)
        return findings

    def _url_to_finding(
        self,
        url: str,
        source: str,
        timestamp: str | None = None,
        status_code: str | None = None,
        mimetype: str | None = None,
    ) -> Finding:
        """Convert a URL to a Finding with appropriate metadata."""
        # Determine if this is an "interesting" URL worth highlighting
        is_interesting = self._is_interesting_path(url)

        metadata: dict[str, Any] = {"interesting": is_interesting}
        if timestamp:
            metadata["timestamp"] = timestamp
        if status_code:
            try:
                metadata["status_code"] = int(status_code)
            except (ValueError, TypeError):
                metadata["status_code"] = status_code
        if mimetype:
            metadata["mimetype"] = mimetype

        return Finding(
            type=FindingType.URL_HISTORICAL,
            value=url,
            source=source,
            confidence=0.9,
            finding_metadata=metadata,
        )

    def _is_interesting_path(self, url: str) -> bool:
        """Check if a URL path matches any of the INTERESTING_PATH_PATTERNS."""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in INTERESTING_PATH_PATTERNS)

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        """Dedupe by URL value, preserving the highest-confidence entry per URL."""
        by_url: dict[str, Finding] = {}
        for f in findings:
            if f.value not in by_url:
                by_url[f.value] = f
            elif f.confidence > by_url[f.value].confidence:
                by_url[f.value] = f
            elif (
                f.finding_metadata.get("timestamp")
                and not by_url[f.value].finding_metadata.get("timestamp")
            ):
                by_url[f.value] = f
        return list(by_url.values())


__all__ = ["WaybackMachineModule"]
