"""Tests for the SOCMINT module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.socmint import SOCIAL_PLATFORMS, SOCMINTModule


@pytest.fixture
def module() -> SOCMINTModule:
    return SOCMINTModule()


# ---- _check_platform ----

@pytest.mark.asyncio
async def test_check_platform_200(module: SOCMINTModule) -> None:
    """HTTP 200 response returns the URL (profile exists)."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.head(url__regex=r".*linkedin.com/.*").mock(
            return_value=httpx.Response(200)
        )
        url = await module._check_platform("linkedin", "https://www.linkedin.com/company/{target}", "acme")
    assert url == "https://www.linkedin.com/company/acme"


@pytest.mark.asyncio
async def test_check_platform_404(module: SOCMINTModule) -> None:
    """HTTP 404 returns None (profile doesn't exist)."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.head(url__regex=r".*linkedin.com/.*").mock(
            return_value=httpx.Response(404)
        )
        url = await module._check_platform("linkedin", "https://www.linkedin.com/company/{target}", "nonexistent")
    assert url is None


@pytest.mark.asyncio
async def test_check_platform_405_fallback_to_get(module: SOCMINTModule) -> None:
    """HEAD returns 405 → fallback to GET (some sites don't support HEAD)."""
    head_response = httpx.Response(405)
    get_response = httpx.Response(200)

    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.head(url__regex=r".*linkedin.com/.*").mock(return_value=head_response)
        mock_router.get(url__regex=r".*linkedin.com/.*").mock(return_value=get_response)
        url = await module._check_platform("linkedin", "https://www.linkedin.com/company/{target}", "acme")
    assert url == "https://www.linkedin.com/company/acme"


@pytest.mark.asyncio
async def test_check_platform_connection_error(module: SOCMINTModule) -> None:
    """Connection error returns None."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.head(url__regex=r".*linkedin.com/.*").mock(
            side_effect=httpx.ConnectError("down")
        )
        url = await module._check_platform("linkedin", "https://www.linkedin.com/company/{target}", "acme")
    assert url is None


# ---- Run ----

@pytest.mark.asyncio
async def test_run_finds_multiple_profiles(module: SOCMINTModule) -> None:
    """Multiple platforms report profile existence."""
    # Patch all _check_platform calls to return success for first 2, 404 for rest
    call_count = 0

    async def fake_check(platform_name: str, url_template: str, target: str) -> str | None:
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return url_template.format(target=target)
        return None  # 404 for rest

    with patch.object(module, "_check_platform", side_effect=fake_check):
        result = await module.run(ModuleInput(target="acmecorp"))

    assert call_count == len(SOCIAL_PLATFORMS)  # all platforms checked
    assert len(result.findings) == 2  # only first 2 found
    assert all(f.finding_metadata["platform"] in ("linkedin", "github_org") for f in result.findings)


@pytest.mark.asyncio
async def test_run_no_profiles_found(module: SOCMINTModule) -> None:
    """If all platforms return 404, no findings + errors for failures."""
    async def fake_check(platform_name: str, url_template: str, target: str) -> str | None:
        return None

    with patch.object(module, "_check_platform", side_effect=fake_check):
        result = await module.run(ModuleInput(target="example.com"))

    assert result.findings == []


@pytest.mark.asyncio
async def test_run_handles_exceptions(module: SOCMINTModule) -> None:
    """A platform raising an exception doesn't crash the whole module."""
    async def fake_check(platform_name: str, url_template: str, target: str) -> str | None:
        if platform_name == "linkedin":
            raise RuntimeError("linkedin down")
        if platform_name == "github_org":
            return url_template.format(target=target)
        return None

    with patch.object(module, "_check_platform", side_effect=fake_check):
        result = await module.run(ModuleInput(target="acme"))

    # linkedin failed (error logged), github_org succeeded
    assert len(result.findings) == 1
    assert any("linkedin" in e for e in result.errors)


# ---- Metadata ----

def test_module_metadata(module: SOCMINTModule) -> None:
    assert module.name == "socmint"
    assert module.tier.value == "tier_3"
    assert module.requires_consent is True


def test_social_platforms_includes_known(module: SOCMINTModule) -> None:
    """SOCIAL_PLATFORMS includes the well-known sites."""
    platform_names = {p[0] for p in SOCIAL_PLATFORMS}
    assert "linkedin" in platform_names
    assert "github_org" in platform_names
    assert "twitter" in platform_names