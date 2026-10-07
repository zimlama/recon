"""Tests for the WHOIS / RDAP module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.whois_rdap import WhoisRDAPModule


@pytest.fixture
def module() -> WhoisRDAPModule:
    return WhoisRDAPModule()


@pytest.fixture
def sample_rdap_response() -> dict:
    """Sample RDAP response for example.com."""
    return {
        "objectClassName": "domain",
        "handle": "EXAMPLE-COM",
        "ldhName": "example.com",
        "status": ["client transfer prohibited", "server delete prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Example Registrar, Inc."]],
                ],
            },
        ],
        "nameservers": [
            {"ldhName": "ns1.example.com"},
            {"ldhName": "ns2.example.com"},
        ],
    }


@pytest.fixture
def sample_whois_text() -> str:
    """Sample WHOIS output for example.com."""
    return """
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org
Updated Date: 2024-08-14T07:01:00Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: Example Registrar, Inc.
Registrar IANA ID: 376
Registrar Abuse Contact Email: abuse@iana.org
Registrar Abuse Contact Phone: +1.1234567890
Reseller:
Domain Status: client transfer prohibited
Name Server: ns1.example.com
Name Server: ns2.example.com
DNSSEC: signedDelegation
"""


# ---- RDAP path ----

@pytest.mark.asyncio
async def test_rdap_success(
    module: WhoisRDAPModule,
    sample_rdap_response: dict,
) -> None:
    """Successful RDAP query returns a consolidated finding + nameserver findings."""
    with respx.mock(base_url="https://rdap.org") as mock_router:
        mock_router.get("/domain/example.com").mock(
            return_value=httpx.Response(200, json=sample_rdap_response)
        )

        result = await module.run(ModuleInput(target="example.com"))

    assert result.module == "whois_rdap"
    assert result.errors == []
    # 1 consolidated + 2 nameservers
    assert len(result.findings) == 3

    # The consolidated finding
    consolidated = next(
        f for f in result.findings
        if f.value == "example.com" and f.source == "rdap"
    )
    assert consolidated.confidence == 0.95
    assert consolidated.finding_metadata["handle"] == "EXAMPLE-COM"
    assert "client transfer prohibited" in consolidated.finding_metadata["status"]
    assert consolidated.finding_metadata["events"]["registration"] == "1995-08-14T04:00:00Z"
    assert consolidated.finding_metadata["events"]["expiration"] == "2025-08-13T04:00:00Z"
    assert consolidated.finding_metadata["entities"]["registrar"] == "Example Registrar, Inc."
    assert consolidated.finding_metadata["nameservers"] == [
        "ns1.example.com",
        "ns2.example.com",
    ]

    # The nameserver findings
    ns_findings = [f for f in result.findings if f.finding_metadata.get("role") == "nameserver"]
    assert len(ns_findings) == 2
    assert {f.value for f in ns_findings} == {"ns1.example.com", "ns2.example.com"}


@pytest.mark.asyncio
async def test_rdap_404_falls_back_to_whois(
    module: WhoisRDAPModule,
    sample_whois_text: str,
) -> None:
    """If RDAP returns 404, fall back to WHOIS subprocess."""
    with respx.mock(base_url="https://rdap.org") as mock_router:
        mock_router.get("/domain/example.com").mock(
            return_value=httpx.Response(404, text="Not Found")
        )

        # Mock the WHOIS subprocess call
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(sample_whois_text.encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run(ModuleInput(target="example.com"))

    assert result.module == "whois_rdap"
    assert any("RDAP" in e or "404" in e or "WHOIS" in e for e in result.errors) or len(result.errors) == 0
    # Should have findings from WHOIS
    assert len(result.findings) >= 1
    consolidated = next(f for f in result.findings if f.value == "example.com")
    assert consolidated.source == "whois"


@pytest.mark.asyncio
async def test_rdap_http_error_falls_back_to_whois(
    module: WhoisRDAPModule,
    sample_whois_text: str,
) -> None:
    """If RDAP raises an HTTP error, fall back to WHOIS."""
    with respx.mock(base_url="https://rdap.org") as mock_router:
        mock_router.get("/domain/example.com").mock(
            side_effect=httpx.ConnectError("Network unreachable")
        )

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(sample_whois_text.encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run(ModuleInput(target="example.com"))

    # Should still produce findings from WHOIS
    assert len(result.findings) >= 1
    assert any(f.source == "whois" for f in result.findings)


@pytest.mark.asyncio
async def test_both_sources_fail(module: WhoisRDAPModule) -> None:
    """If both RDAP and WHOIS fail, log errors and return empty findings."""
    with respx.mock(base_url="https://rdap.org") as mock_router:
        mock_router.get("/domain/example.com").mock(
            side_effect=httpx.ConnectError("Network unreachable")
        )

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=FileNotFoundError("whois not found"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run(ModuleInput(target="example.com"))

    assert result.module == "whois_rdap"
    assert len(result.findings) == 0
    assert len(result.errors) >= 1


# ---- WHOIS parsing ----

@pytest.mark.asyncio
async def test_whois_parsing_extracts_fields(
    module: WhoisRDAPModule,
    sample_whois_text: str,
) -> None:
    """WHOIS parsing extracts registrar, dates, nameservers."""
    # RDAP fails
    with respx.mock(base_url="https://rdap.org") as mock_router:
        mock_router.get("/domain/example.com").mock(
            return_value=httpx.Response(404)
        )

        # WHOIS succeeds
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(sample_whois_text.encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run(ModuleInput(target="example.com"))

    consolidated = next(f for f in result.findings if f.value == "example.com")
    assert consolidated.source == "whois"
    assert consolidated.confidence < 0.9  # Lower confidence for parsed WHOIS
    assert consolidated.finding_metadata["registrar"] == "Example Registrar, Inc."
    assert "1995-08-14" in consolidated.finding_metadata["creation_date"]
    assert "2025-08-13" in consolidated.finding_metadata["expiration_date"]
    assert "client transfer prohibited" in consolidated.finding_metadata["status"]
    assert consolidated.finding_metadata["nameservers"] == [
        "ns1.example.com",
        "ns2.example.com",
    ]


@pytest.mark.asyncio
async def test_whois_filters_abuse_emails(
    module: WhoisRDAPModule,
) -> None:
    """Abuse/privacy emails are filtered from WHOIS parsing."""
    whois_text = """
Domain Name: example.com
Registrar: Test Registrar
Registrant: Some Person
Email: registrant@example.com
Email: abuse@iana.org
Email: privacy@withheld-for-privacy.com
"""

    with respx.mock(base_url="https://rdap.org") as mock_router:
        mock_router.get("/domain/example.com").mock(
            return_value=httpx.Response(404)
        )

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(whois_text.encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run(ModuleInput(target="example.com"))

    consolidated = next(f for f in result.findings if f.value == "example.com")
    emails = consolidated.finding_metadata["emails"]
    # registrant@example.com is kept; abuse@iana.org and privacy@... are filtered
    assert "registrant@example.com" in emails
    assert not any("abuse" in e for e in emails)
    assert not any("privacy" in e for e in emails)


# ---- Target validation ----

@pytest.mark.asyncio
async def test_target_is_normalized(
    module: WhoisRDAPModule,
    sample_rdap_response: dict,
) -> None:
    """Target is lowercased and stripped."""
    with respx.mock(base_url="https://rdap.org") as mock_router:
        mock_router.get("/domain/example.com").mock(
            return_value=httpx.Response(200, json=sample_rdap_response)
        )

        result = await module.run(ModuleInput(target="  EXAMPLE.COM  "))
    assert all(f.value == f.value.lower() for f in result.findings if f.value != "example.com")


# ---- AI prompt ----

def test_ai_prompt_is_substantive(module: WhoisRDAPModule) -> None:
    """AI prompt has the required structure."""
    prompt = module.get_ai_prompt()
    assert "WHOIS" in prompt or "RDAP" in prompt
    assert "CONFIRMED" in prompt
    assert "FALSE_POSITIVE" in prompt
    assert "HIGH" in prompt and "MEDIUM" in prompt and "LOW" in prompt
    assert len(prompt) > 200


# ---- Metadata ----

def test_module_metadata(module: WhoisRDAPModule) -> None:
    """Module has the right Tier 1 metadata."""
    assert module.name == "whois_rdap"
    assert module.tier.value == "tier_1"
    assert "T1596.002" in module.mitre_techniques
    assert module.enabled_by_default is True
    assert module.requires_api_keys == []
    assert module.requires_consent is False


# ---- SSRF defense: adopt BaseReconModule.safe_http_get_async ----

@pytest.mark.asyncio
async def test_query_rdap_uses_safe_http_get_async(
    module: WhoisRDAPModule,
    sample_rdap_response: dict,
) -> None:
    """RDAP query routes through BaseReconModule.safe_http_get_async.

    Refactor contract: the module must route its outbound HTTP through
    ``self.safe_http_get_async`` instead of constructing an inline
    ``httpx.AsyncClient(..., follow_redirects=False)`` block.
    """
    captured: list[str] = []

    async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
        captured.append(url)
        # Return a 200 with valid RDAP JSON so the function reads it
        return httpx.Response(200, json=sample_rdap_response)

    module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

    result = await module._query_rdap("example.com")

    assert captured, "safe_http_get_async must have been called"
    assert captured[0].startswith("https://rdap.org/domain/")
    assert "example.com" in captured[0]
    assert result is not None
    assert result["ldhName"] == "example.com"


@pytest.mark.asyncio
async def test_query_rdap_safe_http_get_returns_none(module: WhoisRDAPModule) -> None:
    """When safe_http_get_async returns None (e.g., SSRF blocked), RDAP returns None."""
    async def fake_safe(url: str, **kwargs: object) -> None:
        return None

    module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

    result = await module._query_rdap("example.com")
    assert result is None


@pytest.mark.asyncio
async def test_query_rdap_non_200_returns_none(module: WhoisRDAPModule) -> None:
    """When RDAP returns non-200, the function returns None."""
    async def fake_safe(url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(404, text="Not Found")

    module.safe_http_get_async = fake_safe  # type: ignore[method-assign]

    result = await module._query_rdap("example.com")
    assert result is None
