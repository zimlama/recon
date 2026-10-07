"""Tests for the GitHub recon module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.github_recon import GITHUB_API_URL, GitHubReconModule


@pytest.fixture
def module() -> GitHubReconModule:
    return GitHubReconModule()


@pytest.fixture
def sample_code_search_response() -> dict:
    """Sample GitHub code search response."""
    return {
        "total_count": 2,
        "items": [
            {
                "name": "config.py",
                "path": "src/config.py",
                "html_url": "https://github.com/acmecorp/api/blob/main/src/config.py",
                "repository": {"full_name": "acmecorp/api"},
            },
            {
                "name": "docker-compose.yml",
                "path": "deploy/docker-compose.yml",
                "html_url": "https://github.com/acmecorp/infra/blob/main/deploy/docker-compose.yml",
                "repository": {"full_name": "acmecorp/infra"},
            },
        ],
    }


@pytest.fixture
def sample_commit_search_response() -> dict:
    return {
        "total_count": 1,
        "items": [
            {
                "sha": "abc123def456789012345678901234567890abcd",
                "html_url": "https://github.com/acmecorp/api/commit/abc123d",
                "repository": {"full_name": "acmecorp/api"},
            }
        ],
    }


# ---- Code search ----

@pytest.mark.asyncio
async def test_code_search_success(
    module: GitHubReconModule,
    sample_code_search_response: dict,
) -> None:
    """GitHub code search returns file findings."""
    with respx.mock(base_url=GITHUB_API_URL) as mock_router:
        mock_router.get("/search/code").mock(
            return_value=httpx.Response(200, json=sample_code_search_response)
        )
        result = await module.run(ModuleInput(target="acmecorp.com"))

    code_findings = [f for f in result.findings if f.source == "github_code_search"]
    assert len(code_findings) == 2
    assert any(f.value == "acmecorp/api/src/config.py" for f in code_findings)
    assert any("acmecorp/infra" in f.value for f in code_findings)


@pytest.mark.asyncio
async def test_code_search_rate_limit(
    module: GitHubReconModule,
) -> None:
    """GitHub 403 (rate limit) is handled gracefully."""
    with respx.mock(base_url=GITHUB_API_URL) as mock_router:
        mock_router.get("/search/code").mock(return_value=httpx.Response(403))
        mock_router.get("/search/commits").mock(return_value=httpx.Response(403))
        result = await module.run(ModuleInput(target="acmecorp.com"))

    # No findings, no errors (403 is silent — rate limit is expected)
    assert result.findings == []
    assert result.errors == []


@pytest.mark.asyncio
async def test_code_search_uses_github_token(
    module: GitHubReconModule,
) -> None:
    """If GITHUB_TOKEN is set, Authorization header is sent."""
    # Patch where it's used (in the module's namespace), not where it's defined
    with patch("app.modules.github_recon.get_settings") as mock_settings:
        settings = MagicMock()
        settings.GITHUB_TOKEN = "ghp_test123"
        mock_settings.return_value = settings

        with respx.mock(base_url=GITHUB_API_URL, assert_all_called=False) as mock_router:
            mock_router.get("/search/code").mock(
                return_value=httpx.Response(200, json={"items": []})
            )
            await module.run(ModuleInput(target="acmecorp.com"))

            # Check the request had the Authorization header
            request = mock_router.calls[0].request
            assert "Authorization" in request.headers
            assert request.headers["Authorization"] == "Bearer ghp_test123"


@pytest.mark.asyncio
async def test_code_search_no_token(
    module: GitHubReconModule,
) -> None:
    """Without GITHUB_TOKEN, no Authorization header is sent."""
    with patch("app.modules.github_recon.get_settings") as mock_settings:
        settings = MagicMock()
        settings.GITHUB_TOKEN = None
        mock_settings.return_value = settings

        with respx.mock(base_url=GITHUB_API_URL, assert_all_called=False) as mock_router:
            mock_router.get("/search/code").mock(
                return_value=httpx.Response(200, json={"items": []})
            )
            await module.run(ModuleInput(target="acmecorp.com"))

            request = mock_router.calls[0].request
            assert "Authorization" not in request.headers


# ---- Commit search ----

@pytest.mark.asyncio
async def test_commit_search_success(
    module: GitHubReconModule,
    sample_commit_search_response: dict,
) -> None:
    """GitHub commit search returns commit findings."""
    with respx.mock(base_url=GITHUB_API_URL) as mock_router:
        mock_router.get("/search/code").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        mock_router.get("/search/commits").mock(
            return_value=httpx.Response(200, json=sample_commit_search_response)
        )
        result = await module.run(ModuleInput(target="acmecorp.com"))

    commit_findings = [f for f in result.findings if f.source == "github_commit_search"]
    assert len(commit_findings) == 1
    assert "abc123d" in commit_findings[0].value


# ---- Secret pattern detection ----

def test_aws_access_key_pattern_detected(module: GitHubReconModule) -> None:
    """AWS access key ID (AKIA...) is detected."""
    from app.modules.base import Finding
    from app.models import FindingType

    # Simulate search result with a file name that contains an AWS key
    with respx.mock(base_url=GITHUB_API_URL) as mock_router:
        mock_router.get("/search/code").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "name": "AKIA1234567890ABCDEF",  # AWS key in name
                            "path": ".env",
                            "html_url": "https://github.com/x/y/blob/main/.env",
                            "repository": {"full_name": "x/y"},
                        }
                    ]
                },
            )
        )
        # Run via asyncio
        import asyncio
        result = asyncio.run(module.run(ModuleInput(target="example.com")))

    # Should detect the secret
    cred_findings = [f for f in result.findings if f.type == FindingType.CREDENTIAL_EXPOSURE]
    assert len(cred_findings) >= 1
    assert any("aws" in f.value for f in cred_findings)


def test_dedupe_dedupes_by_value_and_source(module: GitHubReconModule) -> None:
    from app.modules.base import Finding
    from app.models import FindingType

    f1 = Finding(type=FindingType.OTHER, value="x", source="y", confidence=0.9)
    f2 = Finding(type=FindingType.OTHER, value="x", source="y", confidence=0.9)
    f3 = Finding(type=FindingType.OTHER, value="x", source="z", confidence=0.9)
    deduped = module._dedupe([f1, f2, f3])
    assert len(deduped) == 2


# ---- Metadata ----

def test_module_metadata(module: GitHubReconModule) -> None:
    assert module.name == "github_recon"
    assert module.tier.value == "tier_2"
    assert "T1593.003" in module.mitre_techniques
    assert module.enabled_by_default is False
