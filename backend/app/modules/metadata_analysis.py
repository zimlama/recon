"""Metadata analysis module — Tier 2 (semi-passive).

Extracts EXIF, document metadata (author, software, paths, GPS) from
publicly accessible documents.

Uses `exiftool` (Perl-based, must be installed) for broad format support.
Falls back to a Python-only path (using `python-docx`, `pypdf`) if exiftool
is not available.

MITRE ATT&CK: T1593
"""

from __future__ import annotations

from app.logging import get_logger

import asyncio
import contextlib
import json
import logging
import re
import shutil
import time
from typing import Any, cast
from urllib.parse import urlencode

from app.models import ModuleTier
from app.modules.base import (
    BaseReconModule,
    Finding,
    FindingType,
    ModuleInput,
    ModuleOutput,
    TouchClass,
)

logger = get_logger(__name__)

EXIFTOOL_TIMEOUT = 30
HTTP_TIMEOUT = 15
WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"

# Patterns to extract interesting metadata fields
USERNAME_PATTERNS = re.compile(
    r"(?:author|creator|owner|user)(?:\s*[:=]\s*|\"[^:]*:\s*\"(?!\s*))(?:\\?[\"']?)([A-Za-z0-9._-]{3,})",
    re.IGNORECASE,
)
PATH_PATTERNS = re.compile(
    r"([/\\](?:Users|home|var|opt|srv|workspace)[/\\][A-Za-z0-9._/-]{3,})",
)
INTERNAL_IP_PATTERNS = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
)
SOFTWARE_PATTERNS = re.compile(
    r"(Microsoft Office \d+\.\d+|LibreOffice \d+\.\d+|Adobe (?:Photoshop|Acrobat) \d+\.\d+|"
    r"Google Docs|Python \d+\.\d+|Java \d+\.\d+|PHP \d+\.\d+|\.NET \d+\.\d+)",
)


class MetadataAnalysisModule(BaseReconModule):
    """EXIF + document metadata extraction from public files.

    Note: This module requires finding documents first. For v0.1, we use
    the Wayback Machine to find public documents matching the target.
    Future: integrate with `theHarvester` or `metagoofil`.
    """

    name = "metadata_analysis"
    description = "EXIF + document metadata extraction (exiftool + python-docx/pypdf)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1593"]
    requires_api_keys: list[str] = []
    requires_consent = False
    estimated_duration_seconds = 30
    enabled_by_default = False  # Tier 2 — opt-in
    touch_classification: TouchClass = TouchClass.PASSIVE_THIRDPARTY
    requires_paid: bool = False

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Find public documents for the target, extract metadata."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. Find document URLs via Wayback Machine
        doc_urls = await self._find_documents_via_wayback(target)
        if not doc_urls:
            return ModuleOutput(
                module=self.name,
                findings=findings,
                duration_seconds=time.time() - start,
                errors=["No public documents found via Wayback Machine"],
            )

        # 2. Download and extract metadata from each
        for url in doc_urls[:10]:  # limit to 10 docs
            try:
                metadata = await self._extract_metadata(url)
                if metadata:
                    findings.extend(self._metadata_to_findings(target, url, metadata))
            except Exception as e:
                errors.append(f"Failed to extract metadata from {url}: {e!s}")

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of metadata findings."""
        return """You are validating metadata extraction findings for a target.

For each metadata field (author, software, path, GPS, IP), classify as:
- CONFIRMED: real, current, useful for the engagement
- LIKELY: real but possibly stale
- FALSE_POSITIVE: anonymized, fake, or unrelated
- SUSPECTED: data quality uncertain

Enrich each with:
- value_type: username, hostname, software_version, internal_path, gps_coords, internal_ip
- priority: HIGH (active usernames, current software versions), MEDIUM (paths), LOW (stale)
- reasoning: 1 sentence

Watch for:
- Internal usernames (username reuse → password spray targets)
- Software versions (CVE matching)
- Internal paths (network topology hints)
- GPS coordinates (physical location)
- Printer names (network recon)
- Internal IP addresses (10.x, 172.16.x, 192.168.x)
- VPN/proxy endpoints

PII HANDLING: GPS coordinates are sensitive. Only note country/region unless authorized.

Respond with structured JSON matching the LDMValidationResult schema."""

    # ---- Private helpers ----

    async def _find_documents_via_wayback(self, domain: str) -> list[str]:
        """Find public documents for the target via Wayback CDX.

        SSRF defense: routes through ``BaseReconModule.safe_http_get_async``
        which enforces ``follow_redirects=False`` and swallows httpx errors.
        """
        # Common document file extensions
        doc_extensions = r"\.(?:pdf|docx?|xlsx?|pptx?|odt|ods|odp)$"
        url_pattern = f"{domain}/.*{doc_extensions}"

        params = {
            "url": url_pattern,
            "output": "json",
            "fl": "original,timestamp,mimetype",
            "collapse": "urlkey",
            "limit": 50,
        }
        full_url = f"{WAYBACK_CDX_URL}?{urlencode(params)}"
        try:
            # SSRF defense: safe_http_get_async (follow_redirects=False, swallows HTTPError)
            response = await self.safe_http_get_async(full_url, timeout=HTTP_TIMEOUT)
            if response is None or response.status_code != 200:
                return []
            data = response.json()
        except (ValueError, TypeError):
            return []

        if not data or len(data) < 2:
            return []

        header = data[0]
        try:
            original_idx = header.index("original")
        except ValueError:
            return []

        urls = []
        for row in data[1:]:
            if not row or len(row) <= original_idx:
                continue
            url = row[original_idx]
            if url not in urls:
                urls.append(url)
        return urls

    async def _extract_metadata(self, url: str) -> dict[str, Any] | None:
        """Extract metadata from a document URL.

        Strategy:
        1. Try `exiftool` if installed (best for PDFs, Office docs, images)
        2. Fall back to python-docx (for .docx)
        3. Fall back to pypdf (for .pdf)

        SSRF defense: follow_redirects=False to prevent pivoting to
        internal services via HTTP redirect chain.
        """
        if shutil.which("exiftool"):
            return await self._extract_with_exiftool(url)

        # Python-only fallback
        if url.lower().endswith(".docx"):
            return await self._extract_from_docx(url)
        if url.lower().endswith(".pdf"):
            return await self._extract_from_pdf(url)

        return None

    async def _extract_with_exiftool(self, url: str) -> dict[str, Any] | None:
        """Download URL to temp file, run exiftool, parse JSON output.

        SSRF defense: routes download through ``BaseReconModule.safe_http_get_async``
        (follow_redirects=False, swallows HTTPError).
        """
        import tempfile

        try:
            response = await self.safe_http_get_async(url, timeout=HTTP_TIMEOUT)
            if response is None or response.status_code != 200:
                return None
            content = response.content
        except (ValueError, TypeError):
            return None

        # Write to temp file
        with tempfile.NamedTemporaryFile(suffix=self._ext_from_url(url), delete=False) as f:
            f.write(content)
            tmp_path = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "exiftool",
                "-j",  # JSON output
                "-all",  # all metadata
                tmp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=EXIFTOOL_TIMEOUT)
        except (TimeoutError, OSError):
            return None
        finally:
            import os

            with contextlib.suppress(OSError):
                os.unlink(tmp_path)

        try:
            data = json.loads(stdout.decode("utf-8", errors="replace"))
            if isinstance(data, list) and data:
                return cast(dict[str, Any], data[0])  # exiftool returns a list with one element
        except json.JSONDecodeError:
            return None
        return None

    async def _extract_from_docx(self, url: str) -> dict[str, Any] | None:
        """Extract metadata from .docx using python-docx (if available).

        SSRF defense: routes download through ``BaseReconModule.safe_http_get_async``
        (follow_redirects=False, swallows HTTPError).
        """
        try:
            import io

            import docx  # type: ignore[import-not-found]
        except ImportError:
            return None

        try:
            response = await self.safe_http_get_async(url, timeout=HTTP_TIMEOUT)
            if response is None or response.status_code != 200:
                return None
            doc = docx.Document(io.BytesIO(response.content))
        except Exception:
            return None

        cp = doc.core_properties
        return {
            "Author": cp.author,
            "Title": cp.title,
            "Subject": cp.subject,
            "Keywords": cp.keywords,
            "Comments": cp.comments,
            "LastModifiedBy": cp.last_modified_by,
            "Created": str(cp.created) if cp.created else None,
            "Modified": str(cp.modified) if cp.modified else None,
        }

    async def _extract_from_pdf(self, url: str) -> dict[str, Any] | None:
        """Extract metadata from .pdf using pypdf (if available).

        SSRF defense: routes download through ``BaseReconModule.safe_http_get_async``
        (follow_redirects=False, swallows HTTPError).
        """
        try:
            import io

            import pypdf
        except ImportError:
            return None

        try:
            response = await self.safe_http_get_async(url, timeout=HTTP_TIMEOUT)
            if response is None or response.status_code != 200:
                return None
            reader = pypdf.PdfReader(io.BytesIO(response.content))
            meta = reader.metadata
            if not meta:
                return None
            return {k: str(v) for k, v in meta.items() if v}
        except Exception:
            return None

    def _metadata_to_findings(
        self, target: str, url: str, metadata: dict[str, Any]
    ) -> list[Finding]:
        """Convert extracted metadata to findings (one per interesting field)."""
        findings: list[Finding] = []
        findings.extend(self._username_findings(target, url, metadata))
        findings.extend(self._software_findings(target, url, metadata))
        findings.extend(self._path_and_ip_findings(url, metadata))
        return findings

    def _username_findings(
        self, target: str, url: str, metadata: dict[str, Any]
    ) -> list[Finding]:
        """Author / creator / username fields → username findings."""
        for key in ("Author", "Creator", "LastModifiedBy", "Owner", "User"):
            if metadata.get(key):
                username = str(metadata[key])
                return [
                    Finding(
                        type=FindingType.OTHER,
                        value=username,
                        source="metadata_analysis",
                        confidence=0.85,
                        finding_metadata={
                            "kind": "username",
                            "url": url,
                            "domain": target,
                        },
                    )
                ]
        return []

    def _software_findings(
        self, target: str, url: str, metadata: dict[str, Any]
    ) -> list[Finding]:
        """Software / producer fields → tech stack findings (only with digit hint)."""
        for key in ("Software", "Producer", "Creator", "Application"):
            if metadata.get(key):
                software = str(metadata[key])
                if any(c.isdigit() for c in software):
                    return [
                        Finding(
                            type=FindingType.TECH_STACK,
                            value=software,
                            source="metadata_analysis",
                            confidence=0.9,
                            finding_metadata={
                                "kind": "software",
                                "url": url,
                                "domain": target,
                            },
                        )
                    ]
                return []
        return []

    def _path_and_ip_findings(
        self, url: str, metadata: dict[str, Any]
    ) -> list[Finding]:
        """Scan all metadata values for internal paths and IP addresses."""
        findings: list[Finding] = []
        for key, value in metadata.items():
            if not value:
                continue
            value_str = str(value)
            for path in PATH_PATTERNS.findall(value_str)[:3]:
                findings.append(
                    Finding(
                        type=FindingType.OTHER,
                        value=path,
                        source="metadata_analysis",
                        confidence=0.8,
                        finding_metadata={
                            "kind": "internal_path",
                            "url": url,
                            "field": key,
                        },
                    )
                )
            for ip in INTERNAL_IP_PATTERNS.findall(value_str)[:3]:
                findings.append(
                    Finding(
                        type=FindingType.IP_ADDRESS,
                        value=ip,
                        source="metadata_analysis",
                        confidence=0.7,
                        finding_metadata={
                            "kind": "internal_ip",
                            "url": url,
                            "field": key,
                        },
                    )
                )
        return findings

    def _ext_from_url(self, url: str) -> str:
        """Get the file extension from a URL (used for temp file naming)."""
        # Strip query params
        path = url.split("?")[0]
        if "." in path.split("/")[-1]:
            return "." + path.split(".")[-1].lower()
        return ".bin"

    __all__ = ["MetadataAnalysisModule"]
