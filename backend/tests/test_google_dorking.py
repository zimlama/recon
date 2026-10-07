"""Tests for the Google Dorking module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.google_dorking import DORK_TEMPLATES, GoogleDorkingModule, SERPAPI_URL


@pytest.fixture
def module() -> GoogleDorkingModule:
    return GoogleDorkingModule()


# ---- Template generation (always runs) ----

@pytest.mark.asyncio
async def test_dork_templates_generated_without_api_key(
    module: GoogleDorkingModule,
) -> None:
    """Dork templates are always returned, even without SERP_API_KEY."""
    import app.config
    with patch.object(app.config, "get_settings") as mock_settings:
        settings = MagicMock()
        settings.SERP_API_KEY = None
        mock_settings.return_value = settings

        result = await module.run(ModuleInput(target="acmecorp.com"))

    template_findings = [f for f in result.findings if f.source == "google_dork_template"]
    assert len(template_findings) == len(DORK_TEMPLATES)
    # Each template is formatted with the target
    assert any("site:acmecorp.com" in f.value for f in template_findings)


@pytest.mark.asyncio
async def test_dork_templates_target_substitution(
    module: GoogleDorkingModule,
) -> None:
    """{target} placeholder is replaced with the actual target domain."""
    import app.config
    with patch.object(app.config, "get_settings") as mock_settings:
        settings = MagicMock()
        settings.SERP_API_KEY = None
        mock_settings.return_value = settings

        result = await module.run(ModuleInput(target="evilcorp.io"))

    template_findings = [f for f in result.findings if f.source == "google_dork_template"]
    for f in template_findings:
        assert "site:evilcorp.io" in f.value
        assert "{target}" not in f.value


def test_categorize_dork_credential(module: GoogleDorkingModule) -> None:
    """Dorks looking for credentials are categorized correctly."""
    assert module._categorize_dork('site:target filetype:env') == "credentials"
    assert module._categorize_dork('site:target "password"') == "credentials"
    assert module._categorize_dork('site:target "API_KEY"') == "credentials"


def test_categorize_dork_backup(module: GoogleDorkingModule) -> None:
    """Dorks looking for backups are categorized correctly."""
    assert module._categorize_dork('site:target filetype:sql') == "backup"
    assert module._categorize_dork('site:target filetype:bak') == "backup"


def test_categorize_dork_admin(module: GoogleDorkingModule) -> None:
    """Dorks looking for admin panels are categorized correctly."""
    assert module._categorize_dork('site:target inurl:admin') == "admin_panel"
    assert module._categorize_dork('site:target inurl:phpmyadmin') == "admin_panel"
    assert module._categorize_dork('site:target inurl:jenkins') == "admin_panel"


def test_categorize_dork_config(module: GoogleDorkingModule) -> None:
    """Dorks looking for config files are categorized correctly."""
    assert module._categorize_dork('site:target inurl:config') == "config"


def test_categorize_dork_exposed_file(module: GoogleDorkingModule) -> None:
    """Dorks looking for generic exposed files (no specific keyword) are categorized correctly."""
    # ext:pdf (no specific keyword like 'xml', 'sql') → exposed_file
    assert module._categorize_dork('site:target ext:pdf') == "exposed_file"
    assert module._categorize_dork('site:target filetype:doc') == "exposed_file"
    # ext:xml has 'xml' keyword → config (more specific match)
    assert module._categorize_dork('site:target ext:xml') == "config"


def test_categorize_dork_other(module: GoogleDorkingModule) -> None:
    """Unknown patterns fall back to 'other'."""
    assert module._categorize_dork('site:target inurl:something_random') == "other"


# ---- SerpAPI search ----

@pytest.mark.asyncio
async def test_serpapi_search_success(module: GoogleDorkingModule) -> None:
    """With SERP_API_KEY, SerpAPI is called and findings returned."""
    # Patch where the module uses get_settings (not where it's defined)
    with patch("app.modules.google_dorking.get_settings") as mock_settings:
        settings = MagicMock()
        settings.SERP_API_KEY = "test-key-123"
        mock_settings.return_value = settings

        serp_response = {
            "organic_results": [
                {
                    "link": "https://example.com/admin/login",
                    "title": "Admin Login - Example",
                    "snippet": "Sign in to your admin account",
                },
                {
                    "link": "https://example.com/.env",
                    "title": "Configuration",
                    "snippet": "DB_PASSWORD=secret",
                },
            ]
        }
        with respx.mock(base_url="https://serpapi.com", assert_all_called=False) as mock_router:
            mock_router.get("/search").mock(return_value=httpx.Response(200, json=serp_response))
            result = await module.run(ModuleInput(target="example.com"))

    serp_findings = [f for f in result.findings if f.source == "serpapi"]
    # 8 priority dorks × 2 mock results = 16 findings (with duplicates)
    assert len(serp_findings) >= 2
    assert any("admin/login" in f.value for f in serp_findings)
    assert any(".env" in f.value for f in serp_findings)


@pytest.mark.asyncio
async def test_serpapi_error_silently_continues(module: GoogleDorkingModule) -> None:
    """SerpAPI errors are caught and the module continues with other queries."""
    with patch("app.modules.google_dorking.get_settings") as mock_settings:
        settings = MagicMock()
        settings.SERP_API_KEY = "test-key-123"
        mock_settings.return_value = settings

        with respx.mock(base_url="https://serpapi.com", assert_all_called=False) as mock_router:
            mock_router.get("/search").mock(side_effect=httpx.ConnectError("API down"))
            result = await module.run(ModuleInput(target="example.com"))

    # Templates still returned
    assert any(f.source == "google_dork_template" for f in result.findings)
    # No crash, no SerpAPI findings
    assert not any(f.source == "serpapi" for f in result.findings)


# ---- Metadata ----

def test_module_metadata(module: GoogleDorkingModule) -> None:
    assert module.name == "google_dorking"
    assert module.tier.value == "tier_2"
    assert "T1593.002" in module.mitre_techniques
    assert module.enabled_by_default is False


def test_ai_prompt_is_substantive(module: GoogleDorkingModule) -> None:
    prompt = module.get_ai_prompt()
    assert "Google" in prompt or "dork" in prompt.lower()
    assert "CONFIRMED" in prompt
    assert "exposed" in prompt.lower() or "admin" in prompt.lower()
    assert "CRITICAL" in prompt  # severity levels mentioned


def test_dork_templates_count(module: GoogleDorkingModule) -> None:
    """At least 10 dork templates (documented in the module)."""
    assert len(DORK_TEMPLATES) >= 10


def test_dork_templates_cover_categories(module: GoogleDorkingModule) -> None:
    """Templates cover credentials, backup, admin, config, exposed_file categories."""
    all_categories = {module._categorize_dork(t) for t in DORK_TEMPLATES}
    assert "credentials" in all_categories
    assert "backup" in all_categories
    assert "admin_panel" in all_categories
    # 'config' OR 'exposed_file' must be present
    assert "config" in all_categories or "exposed_file" in all_categories
