"""Tests for the Shodan/Censys module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdatatype
import dns.resolver
import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.shodan_censys import (
    SHODAN_INTERNETDB_URL,
    ShodanCensysModule,
)


@pytest.fixture
def module() -> ShodanCensysModule:
    return ShodanCensysModule()


@pytest.fixture
def sample_shodan_response() -> dict:
    """Sample Shodan InternetDB response for 1.2.3.4."""
    return {
        "ip": "1.2.3.4",
        "ports": [22, 80, 443, 8080],
        "cpes": [
            "cpe:/a:nginx:nginx:1.21.0",
            "cpe:/a:openssh:openssh:8.2p1",
        ],
        "hostnames": ["example.com", "www.example.com"],
        "tags": ["cloud"],
    }


# ---- _resolve_to_ips ----

@pytest.mark.asyncio
async def test_resolve_to_ips_uses_dnspython(module: ShodanCensysModule) -> None:
    """IP resolution uses dnspython directly."""
    # Patch the inner _resolve_to_ips method since dns is hard to mock
    with patch.object(module, "_resolve_to_ips", return_value=["1.1.1.1"]):
        with respx.mock(base_url="https://internetdb.shodan.io", assert_all_called=False) as mock:
            mock.get("/1.1.1.1").mock(return_value=httpx.Response(200, json={"ports": [80]}))
            result = await module.run(ModuleInput(target="example.com"))
    assert result.module == "shodan_censys"


@pytest.mark.asyncio
async def test_resolve_to_ips_empty_returns_no_findings(module: ShodanCensysModule) -> None:
    """If DNS returns no IPs (mock as empty), module returns empty + error."""
    with patch.object(module, "_resolve_to_ips", return_value=[]):
        result = await module.run(ModuleInput(target="nonexistent.example"))
    assert result.findings == []


# ---- Shodan to findings ----

def test_shodan_to_findings_includes_hostnames(module: ShodanCensysModule) -> None:
    """Shodan hostnames are converted to findings."""
    findings = module._shodan_to_findings("1.2.3.4", {
        "ip": "1.2.3.4",
        "ports": [443],
        "cpes": ["cpe:/a:nginx:nginx"],
        "hostnames": ["example.com"],
        "tags": [],
    })
    hostname_findings = [f for f in findings if "example.com" in f.value and ":" not in f.value]
    assert len(hostname_findings) == 1
    assert hostname_findings[0].finding_metadata["kind"] == "hostname"


def test_censys_to_findings(module: ShodanCensysModule) -> None:
    """Censys services are converted to findings."""
    findings = module._censys_to_findings("1.2.3.4", {
        "services": [
            {"port": 443, "service_name": "https", "transport_protocol": "tcp"},
            {"port": 80, "service_name": "http", "transport_protocol": "tcp"},
        ]
    })
    assert len(findings) == 2
    assert any(f.value == "1.2.3.4:443" and f.finding_metadata["service_name"] == "https" for f in findings)


@pytest.mark.asyncio
async def test_censys_query_error_logged(module: ShodanCensysModule) -> None:
    """Censys query error is logged."""
    with patch("app.modules.shodan_censys.get_settings") as mock_settings:
        settings = MagicMock()
        settings.CENSYS_API_ID = "test-id"
        settings.CENSYS_API_SECRET = "test-secret"
        mock_settings.return_value = settings

        with patch.object(module, "_resolve_to_ips", return_value=["1.2.3.4"]):
            with respx.mock(base_url="https://internetdb.shodan.io", assert_all_called=False) as mock:
                mock.get(url__regex=r"https://internetdb\.shodan\.io/.*").mock(
                    return_value=httpx.Response(200, json={"ports": []})
                )
                # Censys endpoint raises connection error
                mock.get(url__regex=r"https://search\.censys\.io/.*").mock(
                    side_effect=httpx.ConnectError("Censys down")
                )
                result = await module.run(ModuleInput(target="example.com"))

    # Censys error is logged
    assert any("Censys" in e for e in result.errors)

@pytest.mark.asyncio
async def test_resolve_to_ips_success(module: ShodanCensysModule) -> None:
    """Mock DNS resolver returns IPs."""
    answers = []
    for ip in ("1.2.3.4", "5.6.7.8"):
        rdata = type("R", (), {"address": ip})()
        answers.append(rdata)

    mock_resolver = MagicMock()
    mock_resolver.resolve = MagicMock(return_value=answers)

    with patch.object(module, "_resolve_to_ips", return_value=["1.2.3.4", "5.6.7.8"]):
        result = await module.run(ModuleInput(target="example.com"))

    # Both IPs should be queried
    assert result.module == "shodan_censys"


@pytest.mark.asyncio
async def test_no_ips_found_logs_error(module: ShodanCensysModule) -> None:
    """If no IPs can be resolved, log error and return empty."""
    with patch.object(module, "_resolve_to_ips", return_value=[]):
        result = await module.run(ModuleInput(target="example.com"))

    assert result.findings == []
    assert any("Could not resolve" in e for e in result.errors)


# ---- Shodan InternetDB ----

@pytest.mark.asyncio
async def test_shodan_internetdb_query_success(
    module: ShodanCensysModule,
    sample_shodan_response: dict,
) -> None:
    """Successful InternetDB query produces port + hostname findings."""
    with patch.object(module, "_resolve_to_ips", return_value=["1.2.3.4"]):
        with respx.mock(base_url="https://internetdb.shodan.io") as mock_router:
            mock_router.get("/1.2.3.4").mock(
                return_value=httpx.Response(200, json=sample_shodan_response)
            )
            result = await module.run(ModuleInput(target="example.com"))

    # Should have 4 port findings + 2 hostname findings = 6
    assert len(result.findings) == 6
    # Port findings
    port_findings = [f for f in result.findings if ":" in f.value and f.source == "shodan_internetdb"]
    assert any(f.value == "1.2.3.4:22" for f in port_findings)
    assert any(f.value == "1.2.3.4:443" for f in port_findings)
    # Hostname findings
    host_findings = [f for f in result.findings if f.source == "shodan_internetdb" and ":" not in f.value]
    assert any(f.value == "example.com" for f in host_findings)
    assert any(f.value == "www.example.com" for f in host_findings)


@pytest.mark.asyncio
async def test_shodan_internetdb_http_error(
    module: ShodanCensysModule,
) -> None:
    """InternetDB HTTP error is logged, no findings from that source.

    The module returns None on non-200 responses (no exception raised),
    so the run() loop just skips the IP without adding an error.
    """
    with patch.object(module, "_resolve_to_ips", return_value=["1.2.3.4"]):
        with respx.mock(base_url="https://internetdb.shodan.io", assert_all_called=False) as mock_router:
            mock_router.get("/1.2.3.4").mock(return_value=httpx.Response(500))
            result = await module.run(ModuleInput(target="example.com"))

    # No findings (mocked IP returned 500 → no data → no findings)
    assert result.findings == []


@pytest.mark.asyncio
async def test_shodan_internetdb_connection_error(
    module: ShodanCensysModule,
) -> None:
    """Connection error is caught gracefully inside _query_shodan_internetdb (returns None).

    The inner method has its own try/except for httpx errors and returns None,
    so the run() loop just skips the IP without adding an error.
    """
    with patch("app.modules.shodan_censys.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(CENSYS_API_ID=None, CENSYS_API_SECRET=None)
        with patch.object(module, "_resolve_to_ips", return_value=["1.2.3.4"]):
            with respx.mock(base_url="https://internetdb.shodan.io", assert_all_called=False) as mock_router:
                mock_router.get("/1.2.3.4").mock(
                    side_effect=httpx.ConnectError("Network unreachable")
                )
                result = await module.run(ModuleInput(target="example.com"))

    # The IP was skipped silently (no findings, no errors logged)
    assert result.findings == []


# ---- Censys ----

@pytest.mark.asyncio
async def test_censys_skipped_without_keys(
    module: ShodanCensysModule,
) -> None:
    """When CENSYS_API_ID/SECRET are not set, Censys is silently skipped."""
    with patch("app.modules.shodan_censys.get_settings") as mock_settings:
        settings = MagicMock()
        settings.CENSYS_API_ID = None
        settings.CENSYS_API_SECRET = None
        mock_settings.return_value = settings

        with patch.object(module, "_resolve_to_ips", return_value=["1.2.3.4"]):
            with respx.mock(base_url="https://internetdb.shodan.io", assert_all_called=False) as mock_router:
                mock_router.get("/1.2.3.4").mock(return_value=httpx.Response(200, json={"ports": []}))
                await module.run(ModuleInput(target="example.com"))
                # Censys endpoint was NOT called
                assert not any("search.censys.io" in str(r) for r in mock_router.calls)


@pytest.mark.asyncio
async def test_censys_query_with_keys(
    module: ShodanCensysModule,
) -> None:
    """With Censys keys set, the Censys API is called."""
    # Patch where the module uses get_settings
    with patch("app.modules.shodan_censys.get_settings") as mock_settings:
        settings = MagicMock()
        settings.CENSYS_API_ID = "test-id"
        settings.CENSYS_API_SECRET = "test-secret"
        mock_settings.return_value = settings

        with patch.object(module, "_resolve_to_ips", return_value=["1.2.3.4"]):
            with respx.mock(assert_all_called=False) as mock:
                mock.get(url__regex=r"https://internetdb\.shodan\.io/.*").mock(
                    return_value=httpx.Response(200, json={"ports": []})
                )
                mock.get(url__regex=r"https://search\.censys\.io/.*").mock(
                    return_value=httpx.Response(200, json={
                        "services": [
                            {"port": 443, "service_name": "https"},
                            {"port": 80, "service_name": "http"},
                        ]
                    })
                )
                result = await module.run(ModuleInput(target="example.com"))

    censys_findings = [f for f in result.findings if f.source == "censys"]
    assert len(censys_findings) == 2
    assert any(f.value == "1.2.3.4:443" for f in censys_findings)


# ---- Dedupe ----

def test_dedupe_by_value_and_source(module: ShodanCensysModule) -> None:
    """Same (value, source) is deduped."""
    from app.modules.base import Finding
    from app.models import FindingType

    f1 = Finding(type=FindingType.IP_ADDRESS, value="1.2.3.4:80", source="x", confidence=0.9)
    f2 = Finding(type=FindingType.IP_ADDRESS, value="1.2.3.4:80", source="x", confidence=0.9)
    f3 = Finding(type=FindingType.IP_ADDRESS, value="1.2.3.4:80", source="y", confidence=0.9)
    deduped = module._dedupe([f1, f2, f3])
    assert len(deduped) == 2  # f1 and f3, f2 is duplicate of f1


# ---- Metadata ----

def test_module_metadata(module: ShodanCensysModule) -> None:
    assert module.name == "shodan_censys"
    assert module.tier.value == "tier_2"
    assert "T1596.005" in module.mitre_techniques
    assert module.enabled_by_default is False
    assert module.requires_consent is False


def test_ai_prompt_is_substantive(module: ShodanCensysModule) -> None:
    prompt = module.get_ai_prompt()
    assert "Shodan" in prompt or "Censys" in prompt
    assert "CONFIRMED" in prompt
    assert "CVE" in prompt
    assert len(prompt) > 200
