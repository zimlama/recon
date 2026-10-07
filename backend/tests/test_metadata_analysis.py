"""Tests for the metadata analysis module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.metadata_analysis import (
    MetadataAnalysisModule,
    WAYBACK_CDX_URL,
)


@pytest.fixture
def module() -> MetadataAnalysisModule:
    return MetadataAnalysisModule()


@pytest.fixture
def sample_cdx_response() -> list:
    """Sample Wayback CDX response with public documents."""
    return [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode"],
        [
            "com,example)/docs/report.pdf",
            "20240101",
            "https://example.com/docs/report.pdf",
            "application/pdf",
            "200",
        ],
        [
            "com,example)/internal/config.xlsx",
            "20240101",
            "https://example.com/internal/config.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "200",
        ],
    ]


# ---- Wayback CDX document discovery ----

@pytest.mark.asyncio
async def test_wayback_cdx_finds_documents(
    module: MetadataAnalysisModule,
    sample_cdx_response: list,
) -> None:
    """Wayback CDX returns a list of document URLs."""
    with respx.mock(base_url="https://web.archive.org") as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=sample_cdx_response)
        )
        urls = await module._find_documents_via_wayback("example.com")
    assert len(urls) == 2
    assert "https://example.com/docs/report.pdf" in urls
    assert "https://example.com/internal/config.xlsx" in urls


@pytest.mark.asyncio
async def test_wayback_no_documents_found(
    module: MetadataAnalysisModule,
) -> None:
    """Empty CDX response returns no URLs."""
    with respx.mock(base_url="https://web.archive.org") as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=[["urlkey", "timestamp", "original"]])
        )
        urls = await module._find_documents_via_wayback("example.com")
    assert urls == []


@pytest.mark.asyncio
async def test_run_no_documents_returns_empty(
    module: MetadataAnalysisModule,
) -> None:
    """When no documents are found, the module returns empty + error."""
    with patch.object(module, "_find_documents_via_wayback", return_value=[]):
        result = await module.run(ModuleInput(target="example.com"))
    assert result.findings == []
    assert any("No public documents" in e for e in result.errors)


# ---- Metadata → findings conversion ----

def test_metadata_username_extracted(module: MetadataAnalysisModule) -> None:
    """Username from Author field becomes a finding."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "Author": "jane.doe",
            "Software": "Microsoft Office 16.0",
        },
    )
    usernames = [f for f in findings if f.finding_metadata.get("kind") == "username"]
    assert any(f.value == "jane.doe" for f in usernames)


def test_metadata_software_with_version_extracted(module: MetadataAnalysisModule) -> None:
    """Software with version number becomes a TECH_STACK finding."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "Software": "Microsoft Office 16.0",
            "Producer": "Adobe Acrobat 11.0",
        },
    )
    tech_findings = [f for f in findings if f.type.value == "tech_stack"]
    assert any("Microsoft Office 16.0" in f.value for f in tech_findings)


def test_metadata_internal_path_extracted(module: MetadataAnalysisModule) -> None:
    """Internal filesystem paths in metadata become findings."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "Creator": "jane",
            "Comment": "Created at /Users/jane.doe/Documents/internal/report.docx",
        },
    )
    path_findings = [f for f in findings if f.finding_metadata.get("kind") == "internal_path"]
    assert any("/Users/jane.doe" in f.value for f in path_findings)


def test_metadata_internal_ip_extracted(module: MetadataAnalysisModule) -> None:
    """Internal IPs in metadata become findings."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "Comment": "Server: 192.168.1.100, shared: 10.0.0.5",
        },
    )
    ip_findings = [f for f in findings if f.finding_metadata.get("kind") == "internal_ip"]
    assert any(f.value == "192.168.1.100" for f in ip_findings)
    assert any(f.value == "10.0.0.5" for f in ip_findings)


def test_metadata_empty_returns_no_findings(module: MetadataAnalysisModule) -> None:
    """Empty metadata returns no findings."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={},
    )
    assert findings == []


# ---- Extension helper ----

def test_ext_from_url(module: MetadataAnalysisModule) -> None:
    """File extension is extracted from URL."""
    assert module._ext_from_url("https://example.com/file.pdf") == ".pdf"
    assert module._ext_from_url("https://example.com/file.docx?foo=bar") == ".docx"
    assert module._ext_from_url("https://example.com/dir/") == ".bin"


def test_module_metadata(module: MetadataAnalysisModule) -> None:
    assert module.name == "metadata_analysis"
    assert module.tier.value == "tier_2"
    assert "T1593" in module.mitre_techniques
    assert module.enabled_by_default is False


def test_ai_prompt_is_substantive(module: MetadataAnalysisModule) -> None:
    prompt = module.get_ai_prompt()
    assert "metadata" in prompt.lower() or "EXIF" in prompt
    assert "CONFIRMED" in prompt
    assert "username" in prompt.lower() or "GPS" in prompt
    assert "PII" in prompt or "sensitive" in prompt.lower()


# ---- Wayback CDX (additional tests) ----

@pytest.mark.asyncio
async def test_wayback_http_error(
    module: MetadataAnalysisModule,
) -> None:
    """Wayback CDX HTTP error returns empty list."""
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(return_value=httpx.Response(500))
        urls = await module._find_documents_via_wayback("example.com")
    assert urls == []


@pytest.mark.asyncio
async def test_wayback_deduplicates_urls(
    module: MetadataAnalysisModule,
) -> None:
    """Same URL appearing multiple times in CDX response is deduped."""
    cdx_data = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode"],
        [
            "com,example)/doc.pdf",
            "20240101",
            "https://example.com/doc.pdf",
            "application/pdf",
            "200",
        ],
        [
            "com,example)/doc.pdf",
            "20240201",
            "https://example.com/doc.pdf",
            "application/pdf",
            "200",
        ],
    ]
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=cdx_data)
        )
        urls = await module._find_documents_via_wayback("example.com")
    assert len(urls) == 1
    assert urls[0] == "https://example.com/doc.pdf"


# ---- Run with exiftool mocked ----

@pytest.mark.asyncio
async def test_run_with_exiftool_success(
    module: MetadataAnalysisModule,
) -> None:
    """When exiftool is available, the subprocess is invoked and metadata is parsed."""
    # Mock Wayback to return one document
    cdx_data = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode"],
        [
            "com,example)/doc.pdf",
            "20240101",
            "https://example.com/doc.pdf",
            "application/pdf",
            "200",
        ],
    ]
    exiftool_output = json.dumps([{
        "Author": "jane.doe",
        "Software": "Microsoft Office 16.0",
        "CreateDate": "2024:01:01 00:00:00",
    }]).encode()

    # Mock the exiftool subprocess
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(exiftool_output, b""))

    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=cdx_data)
        )
        mock_router.get("https://example.com/doc.pdf").mock(
            return_value=httpx.Response(200, content=b"fake pdf content")
        )
        with patch("shutil.which", return_value="/usr/bin/exiftool"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                result = await module.run(ModuleInput(target="example.com"))

    # Should have findings
    assert len(result.findings) > 0
    # Should have username (jane.doe)
    assert any(f.value == "jane.doe" for f in result.findings)


@pytest.mark.asyncio
async def test_run_with_exiftool_timeout(
    module: MetadataAnalysisModule,
) -> None:
    """When exiftool times out, the error is handled gracefully."""
    cdx_data = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode"],
        [
            "com,example)/doc.pdf",
            "20240101",
            "https://example.com/doc.pdf",
            "application/pdf",
            "200",
        ],
    ]

    # Mock exiftool subprocess that times out
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=TimeoutError())

    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=cdx_data)
        )
        mock_router.get("https://example.com/doc.pdf").mock(
            return_value=httpx.Response(200, content=b"fake pdf content")
        )
        with patch("shutil.which", return_value="/usr/bin/exiftool"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                result = await module.run(ModuleInput(target="example.com"))

    # No crash, document download failed but no findings
    assert any("Failed to extract metadata" in e for e in result.errors) or len(result.findings) == 0
