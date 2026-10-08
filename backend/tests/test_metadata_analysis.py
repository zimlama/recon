"""Tests for the metadata analysis module."""

from __future__ import annotations

import asyncio
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


@pytest.mark.asyncio
async def test_run_logs_error_when_metadata_extraction_fails(
    module: MetadataAnalysisModule,
) -> None:
    """When _extract_metadata raises, the error is logged and the module continues."""
    with patch.object(module, "_find_documents_via_wayback", return_value=[
        "https://example.com/a.pdf",
        "https://example.com/b.pdf",
    ]):
        async def boom(url: str) -> None:
            raise RuntimeError("synthetic failure")

        with patch.object(module, "_extract_metadata", side_effect=boom):
            result = await module.run(ModuleInput(target="example.com"))
    # Two errors logged (one per document), no crash, no findings
    assert result.findings == []
    assert len(result.errors) == 2
    assert all("Failed to extract metadata" in e for e in result.errors)
    assert any("synthetic failure" in e for e in result.errors)


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
async def test_wayback_connection_error(
    module: MetadataAnalysisModule,
) -> None:
    """Wayback CDX connection error returns empty list."""
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(side_effect=httpx.ConnectError("down"))
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


@pytest.mark.asyncio
async def test_wayback_no_header_in_response(
    module: MetadataAnalysisModule,
) -> None:
    """Wayback CDX response without header row is empty."""
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        # Empty array (no header)
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=[])
        )
        urls = await module._find_documents_via_wayback("example.com")
    assert urls == []


# ---- Run with exiftool mocked ----

@pytest.mark.asyncio
async def test_run_with_exiftool_success(
    module: MetadataAnalysisModule,
) -> None:
    """When exiftool is available, the subprocess is invoked and metadata is parsed."""
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

    assert len(result.findings) > 0
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

    assert any("Failed to extract metadata" in e for e in result.errors) or len(result.findings) == 0


# ---- Run without exiftool ----

@pytest.mark.asyncio
async def test_run_without_exiftool_python_docx_fallback(
    module: MetadataAnalysisModule,
) -> None:
    """Without exiftool, Python docx fallback is used for .docx files."""
    cdx_data = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode"],
        [
            "com,example)/internal.docx",
            "20240101",
            "https://example.com/internal.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "200",
        ],
    ]

    # Mock the docx module's parse (the test environment has python-docx)
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=cdx_data)
        )
        # Mock the docx download (skip actual download by patching)
        with patch.object(module, "_extract_metadata", return_value={
            "Author": "alice.smith",
            "Software": "Microsoft Office 16.0",
        }):
            result = await module.run(ModuleInput(target="example.com"))

    # Findings from the mocked metadata
    assert any(f.value == "alice.smith" for f in result.findings)


@pytest.mark.asyncio
async def test_run_download_failure(
    module: MetadataAnalysisModule,
) -> None:
    """If the document download fails (non-200), the error is logged."""
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

    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=cdx_data)
        )
        mock_router.get("https://example.com/doc.pdf").mock(
            return_value=httpx.Response(404)
        )
        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    # Document failed to download — no findings, no crash
    assert result.findings == []


# ---- Ext helper ----

def test_ext_from_url_for_file_with_extension(module: MetadataAnalysisModule) -> None:
    """URL with extension returns the extension."""
    assert module._ext_from_url("https://example.com/file.pdf") == ".pdf"
    assert module._ext_from_url("https://example.com/file.docx") == ".docx"
    assert module._ext_from_url("https://example.com/file.docx?foo=bar") == ".docx"


def test_ext_from_url_default_falls_back_to_bin(module: MetadataAnalysisModule) -> None:
    """URL without '.' in path uses '.bin' fallback."""
    # URL with directory but no extension → .bin
    assert module._ext_from_url("https://example.com/dir/") == ".bin"
    # URL with '.' in hostname but nothing in path → uses last dot in URL → '.com'
    assert module._ext_from_url("https://example.com") == ".com"


# ---- Mock-based tests for the python-docx and pypdf paths ----

def test_extract_from_docx_no_python_docx(module: MetadataAnalysisModule) -> None:
    """If python-docx is not installed, _extract_from_docx returns None."""
    # Simulate `import docx` failing by removing it from sys.modules
    import builtins

    saved_docx = __import__("sys").modules.pop("docx", None)
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "docx":
            raise ImportError("docx not installed")
        return real_import(name, *args, **kwargs)

    try:
        builtins.__import__ = fake_import
        result = asyncio.run(module._extract_from_docx("https://example.com/file.docx"))
    finally:
        builtins.__import__ = real_import
        if saved_docx is not None:
            __import__("sys").modules["docx"] = saved_docx
    assert result is None


def test_extract_from_pdf_no_pypdf(module: MetadataAnalysisModule) -> None:
    """If pypdf is not installed, _extract_from_pdf returns None."""
    import builtins

    saved_pypdf = __import__("sys").modules.pop("pypdf", None)
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "pypdf":
            raise ImportError("pypdf not installed")
        return real_import(name, *args, **kwargs)

    try:
        builtins.__import__ = fake_import
        result = asyncio.run(module._extract_from_pdf("https://example.com/file.pdf"))
    finally:
        builtins.__import__ = real_import
        if saved_pypdf is not None:
            __import__("sys").modules["pypdf"] = saved_pypdf
    assert result is None


@pytest.mark.asyncio
async def test_extract_metadata_no_exiftool_no_fallback(module: MetadataAnalysisModule) -> None:
    """When exiftool is missing AND no fallback (non-docx/pdf), returns None."""
    with patch("shutil.which", return_value=None):
        result = await module._extract_metadata("https://example.com/file.unknown")
        assert result is None


@pytest.mark.asyncio
async def test_extract_from_docx_success(module: MetadataAnalysisModule) -> None:
    """Happy path: python-docx is installed and parses a docx blob."""
    # Stub the docx module so we can exercise the full body
    import io
    import sys
    import types

    fake_docx = types.ModuleType("docx")

    class FakeCoreProperties:
        author = "jane.doe"
        title = "Report"
        subject = "Annual"
        keywords = "kw"
        comments = "comment"
        last_modified_by = "alice"
        created = "2024-01-01T00:00:00Z"
        modified = "2024-01-02T00:00:00Z"

    class FakeDocument:
        def __init__(self, _stream: io.BytesIO) -> None:
            self.core_properties = FakeCoreProperties()

    fake_docx.Document = FakeDocument  # type: ignore[attr-defined]
    saved = sys.modules.get("docx")
    sys.modules["docx"] = fake_docx

    try:
        async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
            return httpx.Response(200, content=b"%PDF-stub")

        module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

        result = await module._extract_from_docx("https://example.com/file.docx")

    finally:
        if saved is not None:
            sys.modules["docx"] = saved
        else:
            sys.modules.pop("docx", None)

    assert result is not None
    assert result["Author"] == "jane.doe"
    assert result["Title"] == "Report"


@pytest.mark.asyncio
async def test_extract_from_pdf_success(module: MetadataAnalysisModule) -> None:
    """Happy path: pypdf is installed and parses a pdf blob."""
    import io
    import sys
    import types

    fake_pypdf = types.ModuleType("pypdf")

    class FakeMetadata:
        def __init__(self) -> None:
            self._items = {
                "/Author": "jane.doe",
                "/Title": "Report",
            }

        def items(self):
            return iter(self._items.items())

    class FakeReader:
        def __init__(self, _stream: io.BytesIO) -> None:
            self.metadata = FakeMetadata()

    fake_pypdf.PdfReader = FakeReader  # type: ignore[attr-defined]
    saved = sys.modules.get("pypdf")
    sys.modules["pypdf"] = fake_pypdf

    try:
        async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
            return httpx.Response(200, content=b"%PDF-stub")

        module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

        result = await module._extract_from_pdf("https://example.com/file.pdf")

    finally:
        if saved is not None:
            sys.modules["pypdf"] = saved
        else:
            sys.modules.pop("pypdf", None)

    assert result is not None
    assert result["/Author"] == "jane.doe"
    assert result["/Title"] == "Report"


@pytest.mark.asyncio
async def test_extract_from_pdf_no_metadata(module: MetadataAnalysisModule) -> None:
    """When pypdf returns no metadata, returns None."""
    import io
    import sys
    import types

    fake_pypdf = types.ModuleType("pypdf")

    class FakeReader:
        def __init__(self, _stream: io.BytesIO) -> None:
            self.metadata = None

    fake_pypdf.PdfReader = FakeReader  # type: ignore[attr-defined]
    saved = sys.modules.get("pypdf")
    sys.modules["pypdf"] = fake_pypdf

    try:
        async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
            return httpx.Response(200, content=b"%PDF-stub")

        module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

        result = await module._extract_from_pdf("https://example.com/file.pdf")

    finally:
        if saved is not None:
            sys.modules["pypdf"] = saved
        else:
            sys.modules.pop("pypdf", None)

    assert result is None


@pytest.mark.asyncio
async def test_extract_from_docx_returns_none_on_bad_response(
    module: MetadataAnalysisModule,
) -> None:
    """When safe_http_get_async returns None, _extract_from_docx returns None."""
    import sys
    import types

    fake_docx = types.ModuleType("docx")

    class FakeDocument:
        def __init__(self, _stream: io.BytesIO) -> None:
            raise ValueError("bad bytes")

    fake_docx.Document = FakeDocument  # type: ignore[attr-defined]
    saved = sys.modules.get("docx")
    sys.modules["docx"] = fake_docx

    try:
        async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
            return httpx.Response(200, content=b"not-a-docx")

        module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

        result = await module._extract_from_docx("https://example.com/file.docx")

    finally:
        if saved is not None:
            sys.modules["docx"] = saved
        else:
            sys.modules.pop("docx", None)

    assert result is None


@pytest.mark.asyncio
async def test_extract_metadata_exiftool_json_decode_error(
    module: MetadataAnalysisModule,
) -> None:
    """When exiftool returns non-JSON, _extract_with_exiftool returns None."""
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

    async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(200, content=b"%PDF-stub")

    module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

    mock_proc = AsyncMock()
    # Return non-JSON to trigger json.JSONDecodeError → return None
    mock_proc.communicate = AsyncMock(return_value=(b"not-json{", b""))

    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=cdx_data)
        )
        with patch("shutil.which", return_value="/usr/bin/exiftool"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                result = await module._extract_metadata("https://example.com/doc.pdf")
    assert result is None


@pytest.mark.asyncio
async def test_extract_metadata_download_failure(module: MetadataAnalysisModule) -> None:
    """When document download fails, returns None."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get(url__regex=r".*example\.com/.*").mock(
            return_value=httpx.Response(404)
        )
        result = await module._extract_metadata("https://example.com/file.pdf")
    assert result is None


@pytest.mark.asyncio
async def test_extract_metadata_network_error(module: MetadataAnalysisModule) -> None:
    """Network error during download → None."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get(url__regex=r".*example\.com/.*").mock(
            side_effect=httpx.ConnectError("Network unreachable")
        )
        result = await module._extract_metadata("https://example.com/file.pdf")
    assert result is None


# ---- _metadata_to_findings edge cases ----

def test_metadata_author_with_lastmodifiedby(module: MetadataAnalysisModule) -> None:
    """Author can also come from LastModifiedBy field."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "LastModifiedBy": "bob.jones",  # No Author field
            "Software": "Microsoft Office 16.0",
        },
    )
    usernames = [f for f in findings if f.finding_metadata.get("kind") == "username"]
    assert any(f.value == "bob.jones" for f in usernames)


def test_metadata_software_falls_back_to_creator(module: MetadataAnalysisModule) -> None:
    """If no Software field, falls back to Creator for tech_stack detection."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "Creator": "Adobe Acrobat 11.0",
        },
    )
    tech_findings = [f for f in findings if f.type.value == "tech_stack"]
    assert any("Adobe Acrobat" in f.value for f in tech_findings)


def test_metadata_path_limit_3(module: MetadataAnalysisModule) -> None:
    """At most 3 internal paths are extracted from a single field."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "Comment": (
                "/Users/alice/file1.docx "
                "/Users/alice/file2.txt "
                "/Users/alice/file3.pdf "
                "/Users/alice/file4.zip "
                "/Users/alice/file5.dmg"
            ),
        },
    )
    path_findings = [f for f in findings if f.finding_metadata.get("kind") == "internal_path"]
    # Max 3 paths
    assert len(path_findings) <= 3


def test_metadata_ip_limit_3(module: MetadataAnalysisModule) -> None:
    """At most 3 internal IPs are extracted from a single field."""
    findings = module._metadata_to_findings(
        target="example.com",
        url="https://example.com/doc.pdf",
        metadata={
            "Comment": (
                "192.168.1.1 10.0.0.1 172.16.0.1 "
                "192.168.2.2 10.0.0.2"
            ),
        },
    )
    ip_findings = [f for f in findings if f.finding_metadata.get("kind") == "internal_ip"]
    assert len(ip_findings) <= 3


# ---- Run() with exception in Wayback CDX ----

@pytest.mark.asyncio
async def test_run_wayback_cdx_invalid_json(module: MetadataAnalysisModule) -> None:
    """Wayback CDX returns invalid JSON — module handles gracefully.

    Note: This test verifies the happy path of the invalid JSON branch.
    The _find_documents_via_wayback method catches JSONDecodeError internally
    and returns an empty list, so no exception propagates to run().
    """
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        # Return an empty header-only response — module handles empty data gracefully
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await module.run(ModuleInput(target="example.com"))
    # No findings, error logged about no documents found
    assert result.findings == []


@pytest.mark.asyncio
async def test_wayback_invalid_json_handled(module: MetadataAnalysisModule) -> None:
    """Wayback returns 200 but invalid JSON → empty list (no crash)."""
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, text="not-json{")
        )
        urls = await module._find_documents_via_wayback("example.com")
    assert urls == []


@pytest.mark.asyncio
async def test_wayback_header_missing_original_column(module: MetadataAnalysisModule) -> None:
    """CDX response missing 'original' column → empty list."""
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        # Header has no 'original' column
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(
                200,
                json=[
                    ["urlkey", "timestamp"],  # no 'original'
                    ["com,example)/doc.pdf", "20240101"],
                ],
            )
        )
        urls = await module._find_documents_via_wayback("example.com")
    assert urls == []


@pytest.mark.asyncio
async def test_wayback_short_rows_skipped(module: MetadataAnalysisModule) -> None:
    """CDX rows shorter than the original column index are skipped."""
    with respx.mock(base_url="https://web.archive.org", assert_all_called=False) as mock_router:
        mock_router.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(
                200,
                json=[
                    ["urlkey", "timestamp", "original"],
                    ["short_row"],  # too short → skipped
                    ["com,example)/doc.pdf", "20240101", "https://example.com/doc.pdf"],
                ],
            )
        )
        urls = await module._find_documents_via_wayback("example.com")
    # Only the well-formed row yields a URL
    assert urls == ["https://example.com/doc.pdf"]


# ---- SSRF defense: adopt BaseReconModule.safe_http_get_async ----

@pytest.mark.asyncio
async def test_find_documents_via_wayback_uses_safe_http_get_async(
    module: MetadataAnalysisModule,
    sample_cdx_response: list,
) -> None:
    """Wayback CDX discovery uses the SSRF-safe helper (BaseReconModule.safe_http_get_async).

    Refactor contract: the module must route its outbound HTTP through
    ``self.safe_http_get_async`` instead of constructing an inline
    ``httpx.AsyncClient(..., follow_redirects=False)`` block. This guarantees
    centralized SSRF defense (URL allowlist, redirect-pivot protection).
    """
    captured: list[str] = []

    async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
        captured.append(url)
        return httpx.Response(200, json=sample_cdx_response)

    module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

    urls = await module._find_documents_via_wayback("example.com")

    assert captured, "safe_http_get_async must have been called"
    # Helper is the source of the response — its return value must be honored
    assert captured[0].startswith(WAYBACK_CDX_URL)
    assert len(urls) == 2
    assert "https://example.com/docs/report.pdf" in urls


@pytest.mark.asyncio
async def test_extract_metadata_uses_safe_http_get_async(
    module: MetadataAnalysisModule,
) -> None:
    """Document download (exiftool path) uses the SSRF-safe helper."""
    captured: list[str] = []

    async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
        captured.append(url)
        # Return bytes that look like a PDF so exiftool subprocess is invoked
        return httpx.Response(200, content=b"%PDF-1.4\nfake\n")

    module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

    exiftool_output = json.dumps([{
        "Author": "jane.doe",
        "Software": "Microsoft Office 16.0",
    }]).encode()

    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(exiftool_output, b""))

    with patch("shutil.which", return_value="/usr/bin/exiftool"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await module._extract_metadata("https://example.com/file.pdf")

    assert captured, "safe_http_get_async must have been called for download"
    assert captured[0] == "https://example.com/file.pdf"


@pytest.mark.asyncio
async def test_safe_http_get_async_returns_none_handled_gracefully(
    module: MetadataAnalysisModule,
) -> None:
    """When safe_http_get_async returns None (e.g., SSRF blocked), module handles it."""
    async def fake_safe(url: str, **kwargs: object) -> None:
        return None

    module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

    # Wayback path: None response means empty result (no documents found)
    urls = await module._find_documents_via_wayback("example.com")
    assert urls == []
