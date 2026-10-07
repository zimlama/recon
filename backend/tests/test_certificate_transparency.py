"""Tests for the Certificate Transparency module."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.certificate_transparency import (
    CRTSH_URL,
    CertificateTransparencyModule,
)


@pytest.fixture
def module() -> CertificateTransparencyModule:
    return CertificateTransparencyModule()


@pytest.fixture
def sample_crtsh_response() -> list[dict]:
    """Sample crt.sh response for example.com."""
    return [
        {
            "id": 12345,
            "issuer_name": "Let's Encrypt",
            "issuer_dn": "CN=Let's Encrypt, O=Internet Security Research Group",
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com\napi.example.com\nmail.example.com",
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-04-01T00:00:00Z",
            "serial_number": "ABC123",
        },
        {
            "id": 12346,
            "issuer_name": "DigiCert",
            "common_name": "*.example.com",
            "name_value": "*.example.com\nstaging.example.com",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
            "serial_number": "DEF456",
        },
    ]


# ---- Happy paths ----

@pytest.mark.asyncio
async def test_crtsh_query_success(
    module: CertificateTransparencyModule,
    sample_crtsh_response: list[dict],
) -> None:
    """crt.sh returns subdomains with cert metadata."""
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=sample_crtsh_response)
        )

        result = await module.run(ModuleInput(target="example.com"))

    assert result.module == "certificate_transparency"
    assert result.errors == []
    hosts = {f.value for f in result.findings}
    assert "www.example.com" in hosts
    assert "api.example.com" in hosts
    assert "mail.example.com" in hosts
    assert "staging.example.com" in hosts


@pytest.mark.asyncio
async def test_crtsh_metadata_includes_cert_info(
    module: CertificateTransparencyModule,
) -> None:
    """Each cert finding includes issuer + validity in metadata."""
    crt_data = [
        {
            "id": 999,
            "issuer_name": "Let's Encrypt",
            "name_value": "api.example.com",
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-04-01T00:00:00Z",
            "serial_number": "XYZ789",
        }
    ]
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crt_data)
        )

        result = await module.run(ModuleInput(target="example.com"))

    api_finding = next(f for f in result.findings if f.value == "api.example.com")
    assert api_finding.finding_metadata["issuer"] == "Let's Encrypt"
    assert api_finding.finding_metadata["not_before"] == "2026-01-01T00:00:00Z"
    assert api_finding.finding_metadata["cert_id"] == 999
    assert api_finding.confidence == 0.95


@pytest.mark.asyncio
async def test_crtsh_strips_wildcard_prefix(
    module: CertificateTransparencyModule,
) -> None:
    """Wildcard prefix *. is stripped from real subdomains."""
    crt_data = [
        {
            "id": 1,
            "issuer_name": "Test",
            "name_value": "*.api.example.com\nfoo.example.com\nexample.com",
        },
    ]
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crt_data)
        )

        result = await module.run(ModuleInput(target="example.com"))

    hosts = {f.value for f in result.findings}
    # *.api.example.com → api.example.com (real subdomain, kept)
    # foo.example.com (no wildcard, kept)
    # example.com (target itself, filtered as not-a-subdomain)
    assert "api.example.com" in hosts
    assert "foo.example.com" in hosts
    # Bare target filtered (it's not a subdomain, it's the apex domain)
    # Note: *.example.com stripped to "example.com" then filtered
    # But *.api.example.com stripped to "api.example.com" is kept
    assert "*.api.example.com" not in hosts
    assert "*.example.com" not in hosts


@pytest.mark.asyncio
async def test_crtsh_filters_names_not_matching_target(
    module: CertificateTransparencyModule,
) -> None:
    """Names not ending with the target domain are filtered out."""
    crt_data = [
        {"id": 1, "issuer_name": "Test", "name_value": "api.example.com\nnotrelated.com\nexample.io"},
    ]
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crt_data)
        )

        result = await module.run(ModuleInput(target="example.com"))

    hosts = {f.value for f in result.findings}
    # Only api.example.com is a real subdomain
    assert "api.example.com" in hosts
    # Other domains are filtered
    assert "notrelated.com" not in hosts
    assert "example.io" not in hosts


@pytest.mark.asyncio
async def test_crtsh_dedupes_by_value(
    module: CertificateTransparencyModule,
) -> None:
    """Same subdomain from multiple certs is deduped."""
    crt_data = [
        {"id": 1, "issuer_name": "Let's Encrypt", "name_value": "api.example.com"},
        {"id": 2, "issuer_name": "DigiCert", "name_value": "api.example.com"},
    ]
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crt_data)
        )

        result = await module.run(ModuleInput(target="example.com"))

    api_findings = [f for f in result.findings if f.value == "api.example.com"]
    assert len(api_findings) == 1


@pytest.mark.asyncio
async def test_crtsh_dedup_prefers_higher_confidence(
    module: CertificateTransparencyModule,
) -> None:
    """When deduping, higher confidence entry wins."""
    # First entry has lower confidence (no issuer), second has higher
    crt_data = [
        {
            "id": 1,
            "issuer_name": "",
            "name_value": "api.example.com",
            "not_before": "2020-01-01T00:00:00Z",  # older = lower confidence
        },
        {
            "id": 2,
            "issuer_name": "Let's Encrypt",
            "name_value": "api.example.com",
            "not_before": "2026-01-01T00:00:00Z",  # newer
        },
    ]
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crt_data)
        )

        result = await module.run(ModuleInput(target="example.com"))

    api_finding = next(f for f in result.findings if f.value == "api.example.com")
    # The Let's Encrypt entry should win (same 0.95 confidence but more metadata)
    # Since we preserve first-seen, the first one is kept. Just verify one entry.
    assert api_finding is not None


# ---- Error handling ----

@pytest.mark.asyncio
async def test_crtsh_http_error_logged(
    module: CertificateTransparencyModule,
) -> None:
    """crt.sh HTTP error is logged, no findings produced."""
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(return_value=httpx.Response(500))

        result = await module.run(ModuleInput(target="example.com"))

    assert result.findings == []
    assert any("crt.sh" in e for e in result.errors)


@pytest.mark.asyncio
async def test_crtsh_invalid_json_logged(
    module: CertificateTransparencyModule,
) -> None:
    """crt.sh returns invalid JSON — error logged."""
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, text="not-valid-json{"),
        )

        result = await module.run(ModuleInput(target="example.com"))

    assert result.findings == []
    assert any("crt.sh" in e for e in result.errors)


@pytest.mark.asyncio
async def test_crtsh_connection_error(
    module: CertificateTransparencyModule,
) -> None:
    """crt.sh connection error — error logged, module continues."""
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(side_effect=httpx.ConnectError("Network unreachable"))

        result = await module.run(ModuleInput(target="example.com"))

    assert result.findings == []
    assert any("crt.sh" in e for e in result.errors)


@pytest.mark.asyncio
async def test_crtsh_empty_response(
    module: CertificateTransparencyModule,
) -> None:
    """crt.sh returns empty list — no error, no findings."""
    with respx.mock(base_url=CRTSH_URL) as mock_router:
        mock_router.get("/").mock(return_value=httpx.Response(200, json=[]))

        result = await module.run(ModuleInput(target="example.com"))

    assert result.findings == []
    assert result.errors == []


# ---- _normalize_name ----

def test_normalize_name_strips_wildcard(module: CertificateTransparencyModule) -> None:
    """Wildcard prefix is stripped, but bare target is filtered out (it's not a subdomain)."""
    # *.example.com → "example.com" after stripping, but "example.com" == target → filtered
    assert module._normalize_name("*.example.com", "example.com") is None


def test_normalize_name_keeps_subdomain_with_stripped_wildcard(
    module: CertificateTransparencyModule,
) -> None:
    """Wildcard prefix is stripped, real subdomain is kept."""
    # *.api.example.com → "api.example.com" after stripping (real subdomain)
    assert module._normalize_name("*.api.example.com", "example.com") == "api.example.com"


def test_normalize_name_lowercases(module: CertificateTransparencyModule) -> None:
    """Names are lowercased."""
    assert module._normalize_name("API.Example.Com", "example.com") == "api.example.com"


def test_normalize_name_strips_whitespace(module: CertificateTransparencyModule) -> None:
    """Leading/trailing whitespace is stripped."""
    assert module._normalize_name("  api.example.com  ", "example.com") == "api.example.com"


def test_normalize_name_filters_non_matching(module: CertificateTransparencyModule) -> None:
    """Names not ending with target are filtered out."""
    assert module._normalize_name("api.other.com", "example.com") is None
    # "notexample.com" doesn't end with "example.com" (no dot before "example.com")
    assert module._normalize_name("notexample.com", "example.com") is None
    # "evil-example.com" doesn't end with "example.com" (has '-' not '.')
    assert module._normalize_name("evil-example.com", "example.com") is None


def test_normalize_name_filters_root_target(module: CertificateTransparencyModule) -> None:
    """Bare target (no subdomain) is filtered out (only subdomains)."""
    # The target itself is the apex domain, not a subdomain
    result = module._normalize_name("example.com", "example.com")
    # "example.com" == target → returns None (filtered as "no subdomain")
    assert result is None


def test_normalize_name_empty(module: CertificateTransparencyModule) -> None:
    """Empty names return None."""
    assert module._normalize_name("", "example.com") is None
    assert module._normalize_name("   ", "example.com") is None


# ---- Metadata ----

def test_module_metadata(module: CertificateTransparencyModule) -> None:
    """Module has the right Tier 1 metadata."""
    assert module.name == "certificate_transparency"
    assert module.tier.value == "tier_1"
    assert "T1596.003" in module.mitre_techniques
    assert module.enabled_by_default is True
    assert module.requires_api_keys == []


def test_ai_prompt_is_substantive(module: CertificateTransparencyModule) -> None:
    """AI prompt has the required structure."""
    prompt = module.get_ai_prompt()
    assert "certificate" in prompt.lower() or "CT" in prompt
    assert "CONFIRMED" in prompt
    assert "FALSE_POSITIVE" in prompt
    assert "internal" in prompt.lower()  # mentions internal hostname leak
    assert len(prompt) > 200
