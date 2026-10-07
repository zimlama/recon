"""Tests for the Wayback Machine module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.wayback_machine import (
    CDX_API_URL,
    INTERESTING_PATH_PATTERNS,
    WaybackMachineModule,
)


@pytest.fixture
def module() -> WaybackMachineModule:
    return WaybackMachineModule()


@pytest.fixture
def sample_cdx_response() -> list:
    """Sample CDX API response (header + data rows)."""
    return [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        [
            "com,example)/",
            "20240101000000",
            "http://example.com/",
            "text/html",
            "200",
            "ABC123",
            "1024",
        ],
        [
            "com,example)/admin",
            "20240101000001",
            "http://example.com/admin",
            "text/html",
            "200",
            "DEF456",
            "2048",
        ],
        [
            "com,example)/api/v1/users",
            "20240101000002",
            "http://example.com/api/v1/users",
            "application/json",
            "200",
            "GHI789",
            "512",
        ],
        [
            "com,example)/.git/config",
            "20240101000003",
            "http://example.com/.git/config",
            "text/plain",
            "200",
            "JKL012",
            "256",
        ],
    ]


# ---- CDX API path ----

@pytest.mark.asyncio
async def test_cdx_query_success(
    module: WaybackMachineModule,
    sample_cdx_response: list,
) -> None:
    """CDX API returns URLs with metadata."""
    with respx.mock(base_url=CDX_API_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=sample_cdx_response)
        )

        with patch("shutil.which", return_value=None):  # no gau/waybackurls
            result = await module.run(ModuleInput(target="example.com"))

    assert result.module == "wayback_machine"
    assert result.errors == []
    assert any(f.source == "wayback_cdx" for f in result.findings)

    # All 4 URLs converted to findings
    urls = {f.value for f in result.findings}
    assert "http://example.com/" in urls
    assert "http://example.com/admin" in urls
    assert "http://example.com/api/v1/users" in urls
    assert "http://example.com/.git/config" in urls


@pytest.mark.asyncio
async def test_cdx_metadata_includes_timestamp_and_status(
    module: WaybackMachineModule,
    sample_cdx_response: list,
) -> None:
    """CDX findings include timestamp, status code, mimetype."""
    with respx.mock(base_url=CDX_API_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=sample_cdx_response)
        )

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    admin_finding = next(f for f in result.findings if "/admin" in f.value)
    assert admin_finding.finding_metadata["timestamp"] == "20240101000001"
    assert admin_finding.finding_metadata["status_code"] == 200
    assert admin_finding.finding_metadata["mimetype"] == "text/html"
    # /admin is an "interesting" path
    assert admin_finding.finding_metadata["interesting"] is True


@pytest.mark.asyncio
async def test_cdx_http_error(
    module: WaybackMachineModule,
) -> None:
    """CDX HTTP error is handled."""
    with respx.mock(base_url=CDX_API_URL) as mock_router:
        mock_router.get("/").mock(return_value=httpx.Response(500))

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    assert any("gau" in e or "waybackurls" in e or "CDX" in e for e in result.errors)


@pytest.mark.asyncio
async def test_cdx_invalid_json(
    module: WaybackMachineModule,
) -> None:
    """CDX returns invalid JSON."""
    with respx.mock(base_url=CDX_API_URL) as mock_router:
        mock_router.get("/").mock(return_value=httpx.Response(200, text="not-json{"))

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    # No error, just no findings
    assert result.findings == []


@pytest.mark.asyncio
async def test_cdx_empty_response(
    module: WaybackMachineModule,
) -> None:
    """CDX returns empty response (just header or no data)."""
    with respx.mock(base_url=CDX_API_URL) as mock_router:
        # Just header, no data rows
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=[["urlkey", "timestamp", "original"]])
        )

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    assert result.findings == []


@pytest.mark.asyncio
async def test_cdx_uses_url_wildcard(
    module: WaybackMachineModule,
) -> None:
    """CDX query uses url={domain}/* pattern."""
    with respx.mock(base_url=CDX_API_URL) as mock_router:
        mock_router.get("/").mock(return_value=httpx.Response(200, json=[]))

        with patch("shutil.which", return_value=None):
            await module.run(ModuleInput(target="example.com"))

        # Verify the request was made with url=example.com/*
        request = mock_router.calls[0].request
        assert "url=example.com" in str(request.url)


# ---- gau/waybackurls subprocess path ----

@pytest.mark.asyncio
async def test_gau_subprocess_success(
    module: WaybackMachineModule,
) -> None:
    """gau subprocess returns URLs."""
    stdout_data = b"http://example.com/\nhttp://example.com/page1\nhttp://example.com/page2\n"
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(stdout_data, b""))

    def which_side_effect(tool: str) -> str:
        # Only gau installed, not waybackurls
        return "/usr/bin/gau" if tool == "gau" else None

    with patch("shutil.which", side_effect=which_side_effect):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with respx.mock(base_url=CDX_API_URL) as mock_router:
                # CDX fails but gau succeeded
                mock_router.get("/").mock(side_effect=httpx.ConnectError("fail"))
                result = await module.run(ModuleInput(target="example.com"))

    assert any(f.source == "gau" for f in result.findings)
    urls = {f.value for f in result.findings}
    assert "http://example.com/page1" in urls
    assert "http://example.com/page2" in urls
    # waybackurls not installed → no waybackurls findings
    assert not any(f.source == "waybackurls" for f in result.findings)


@pytest.mark.asyncio
async def test_waybackurls_subprocess_success(
    module: WaybackMachineModule,
) -> None:
    """waybackurls subprocess returns URLs (with different URL set than gau)."""
    # waybackurls returns DIFFERENT URLs than gau would, so dedup doesn't merge them
    stdout_data = (
        b"http://example.com/old-page1\n"  # unique to waybackurls
        b"http://example.com/old-page2\n"
    )
    mock_proc_gau = AsyncMock()
    mock_proc_gau.communicate = AsyncMock(
        return_value=(b"http://example.com/shared\n", b"")
    )
    mock_proc_wburls = AsyncMock()
    mock_proc_wburls.communicate = AsyncMock(return_value=(stdout_data, b""))

    # Return different mocks for each tool call
    def exec_side_effect(*args, **kwargs):
        if args and args[0] == "gau":
            return mock_proc_gau
        return mock_proc_wburls

    def which_side_effect(tool: str) -> str:
        return f"/usr/bin/{tool}"  # report both tools as installed

    with patch("shutil.which", side_effect=which_side_effect):
        with patch("asyncio.create_subprocess_exec", side_effect=exec_side_effect):
            with respx.mock(base_url=CDX_API_URL) as mock_router:
                mock_router.get("/").mock(side_effect=httpx.ConnectError("fail"))
                result = await module.run(ModuleInput(target="example.com"))

    # Both sources contribute findings
    assert any(f.source == "waybackurls" for f in result.findings)
    assert any(f.value == "http://example.com/old-page1" for f in result.findings)


@pytest.mark.asyncio
async def test_subprocess_timeout(
    module: WaybackMachineModule,
) -> None:
    """Subprocess timeout is caught."""
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=TimeoutError())

    with patch("shutil.which", return_value="/usr/bin/gau"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with respx.mock(base_url=CDX_API_URL) as mock_router:
                mock_router.get("/").mock(side_effect=httpx.ConnectError("fail"))
                result = await module.run(ModuleInput(target="example.com"))

    # gau failed but no error reported (just no findings from it)
    assert not any(f.source == "gau" for f in result.findings)


# ---- Dedupe ----

def test_dedupe_prefers_higher_confidence(module: WaybackMachineModule) -> None:
    """When same URL from multiple sources, higher-confidence wins."""
    from app.modules.base import Finding
    from app.models import FindingType

    findings = [
        Finding(
            type=FindingType.URL_HISTORICAL,
            value="http://example.com/admin",
            source="gau",
            confidence=0.85,
        ),
        Finding(
            type=FindingType.URL_HISTORICAL,
            value="http://example.com/admin",
            source="wayback_cdx",
            confidence=0.95,
        ),
    ]
    deduped = module._dedupe(findings)
    assert len(deduped) == 1
    assert deduped[0].source == "wayback_cdx"


# ---- Interesting path detection ----

def test_interesting_path_admin(module: WaybackMachineModule) -> None:
    """/admin path is interesting."""
    assert module._is_interesting_path("http://example.com/admin") is True
    assert module._is_interesting_path("http://example.com/administrator") is True


def test_interesting_path_api(module: WaybackMachineModule) -> None:
    """/api path is interesting."""
    assert module._is_interesting_path("http://example.com/api/v1/users") is True
    assert module._is_interesting_path("http://example.com/api-docs") is True


def test_interesting_path_sensitive_files(module: WaybackMachineModule) -> None:
    """Backup/config files are interesting."""
    assert module._is_interesting_path("http://example.com/.git/config") is True
    assert module._is_interesting_path("http://example.com/.env") is True
    assert module._is_interesting_path("http://example.com/backup.sql") is True


def test_interesting_path_case_insensitive(module: WaybackMachineModule) -> None:
    """Path detection is case-insensitive."""
    assert module._is_interesting_path("http://example.com/ADMIN") is True
    assert module._is_interesting_path("http://example.com/Admin") is True


def test_uninteresting_path(module: WaybackMachineModule) -> None:
    """Generic pages are not interesting."""
    assert module._is_interesting_path("http://example.com/about") is False
    assert module._is_interesting_path("http://example.com/blog/post-1") is False


def test_interesting_path_patterns_count() -> None:
    """Verify INTERESTING_PATH_PATTERNS is non-trivial."""
    assert len(INTERESTING_PATH_PATTERNS) >= 30  # we documented ~50


# ---- Metadata ----

def test_module_metadata(module: WaybackMachineModule) -> None:
    """Module has the right Tier 1 metadata."""
    assert module.name == "wayback_machine"
    assert module.tier.value == "tier_1"
    assert "T1593" in module.mitre_techniques
    assert module.enabled_by_default is True


def test_ai_prompt_is_substantive(module: WaybackMachineModule) -> None:
    """AI prompt has the required structure."""
    prompt = module.get_ai_prompt()
    assert "Wayback" in prompt or "archive" in prompt.lower()
    assert "CONFIRMED" in prompt
    assert "FALSE_POSITIVE" in prompt
    assert "admin" in prompt.lower() or "API" in prompt
    assert len(prompt) > 200
