"""Tests for the subdomain enumeration module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.subdomain_enum import CRTSH_URL, SubdomainEnumModule


@pytest.fixture
def module() -> SubdomainEnumModule:
    return SubdomainEnumModule()


@pytest.fixture
def sample_crtsh_response() -> list[dict]:
    """Sample crt.sh response for example.com."""
    return [
        {
            "id": 12345,
            "issuer_name": "Let's Encrypt",
            "issuer_dn": "CN=Let's Encrypt, O=Internet Security Research Group",
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com\napi.example.com",
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-04-01T00:00:00Z",
            "serial_number": "ABC123",
        },
        {
            "id": 12346,
            "issuer_name": "DigiCert",
            "common_name": "mail.example.com",
            "name_value": "mail.example.com\n*.example.com",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
            "serial_number": "DEF456",
        },
    ]


# ---- crt.sh path ----

@pytest.mark.asyncio
async def test_crtsh_parses_multiple_names_per_entry(
    module: SubdomainEnumModule,
    sample_crtsh_response: list[dict],
) -> None:
    """crt.sh entries with multiple name_value lines are split correctly."""
    with respx.mock(base_url="https://crt.sh") as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=sample_crtsh_response)
        )

        with patch("shutil.which", return_value=None):  # no subfinder
            result = await module.run(ModuleInput(target="example.com"))

    hosts = {f.value for f in result.findings}
    # Should include: example.com, www, api, mail, and (NOT wildcard, NOT sub-subdomains)
    assert "example.com" in hosts
    assert "www.example.com" in hosts
    assert "api.example.com" in hosts
    assert "mail.example.com" in hosts
    # Wildcard prefix stripped
    assert any(f.value == "example.com" for f in result.findings)
    # The literal "*.example.com" is stripped (lstrip("*."))
    assert not any(f.value == "*.example.com" for f in result.findings)


@pytest.mark.asyncio
async def test_crtsh_strips_wildcard_prefix(
    module: SubdomainEnumModule,
) -> None:
    """Wildcard prefix *. is stripped from names."""
    crtsh_data = [
        {
            "id": 1,
            "issuer_name": "Test",
            "name_value": "*.example.com\nfoo.example.com",
        }
    ]
    with respx.mock(base_url="https://crt.sh") as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crtsh_data)
        )

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    hosts = {f.value for f in result.findings}
    assert "example.com" in hosts  # *. stripped
    assert "foo.example.com" in hosts


@pytest.mark.asyncio
async def test_crtsh_filters_names_not_matching_target(
    module: SubdomainEnumModule,
) -> None:
    """Names not ending with the target domain are filtered out."""
    crtsh_data = [
        {
            "id": 1,
            "issuer_name": "Test",
            "name_value": "example.com\nnotrelated.com\nfoo.bar.com",
        }
    ]
    with respx.mock(base_url="https://crt.sh") as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crtsh_data)
        )

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    hosts = {f.value for f in result.findings}
    assert "example.com" in hosts
    assert "notrelated.com" not in hosts
    assert "foo.bar.com" not in hosts


@pytest.mark.asyncio
async def test_crtsh_metadata_includes_cert_info(
    module: SubdomainEnumModule,
) -> None:
    """crt.sh findings include issuer + validity in metadata."""
    crtsh_data = [
        {
            "id": 999,
            "issuer_name": "Let's Encrypt",
            "name_value": "api.example.com",
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-04-01T00:00:00Z",
            "serial_number": "XYZ789",
        }
    ]
    with respx.mock(base_url="https://crt.sh") as mock_router:
        mock_router.get("/").mock(
            return_value=httpx.Response(200, json=crtsh_data)
        )

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    api_finding = next(f for f in result.findings if f.value == "api.example.com")
    assert api_finding.finding_metadata["issuer"] == "Let's Encrypt"
    assert api_finding.finding_metadata["not_before"] == "2026-01-01T00:00:00Z"
    assert api_finding.finding_metadata["cert_id"] == 999
    assert api_finding.confidence == 0.95


@pytest.mark.asyncio
async def test_crtsh_http_error_logged(
    module: SubdomainEnumModule,
) -> None:
    """crt.sh HTTP error is logged, subfinder fallback or empty result."""
    with respx.mock(base_url="https://crt.sh") as mock_router:
        mock_router.get("/").mock(return_value=httpx.Response(500))

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    assert len(result.findings) == 0
    assert any("crt.sh" in e for e in result.errors)


# ---- subfinder path ----

@pytest.mark.asyncio
async def test_subfinder_parses_json_output(
    module: SubdomainEnumModule,
    sample_crtsh_response: list[dict],
) -> None:
    """subfinder JSON output is parsed correctly."""
    subfinder_lines = [
        json.dumps({"host": "a.example.com", "input": "example.com", "source": "rapiddns"}),
        json.dumps({"host": "b.example.com", "input": "example.com", "source": "crtsh"}),
        json.dumps({"host": "c.example.com", "input": "example.com", "source": "dnsdumpster"}),
    ]
    stdout_data = "\n".join(subfinder_lines).encode()

    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(stdout_data, b""))

    with patch("shutil.which", return_value="/usr/bin/subfinder"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with respx.mock(base_url="https://crt.sh") as mock_router:
                mock_router.get("/").mock(
                    return_value=httpx.Response(200, json=sample_crtsh_response)
                )
                result = await module.run(ModuleInput(target="example.com"))

    subfinder_findings = [f for f in result.findings if f.source == "subfinder"]
    assert len(subfinder_findings) == 3
    assert {f.value for f in subfinder_findings} == {
        "a.example.com", "b.example.com", "c.example.com"
    }
    # Source metadata is preserved
    a = next(f for f in subfinder_findings if f.value == "a.example.com")
    assert a.finding_metadata["source"] == "rapiddns"


@pytest.mark.asyncio
async def test_subfinder_swallows_invalid_json(
    module: SubdomainEnumModule,
) -> None:
    """subfinder output with invalid JSON lines is handled gracefully."""
    stdout_data = b'{"host": "valid.example.com"}\nnot-json-at-all\n{"host": "another.example.com"}\n'
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(stdout_data, b""))

    with patch("shutil.which", return_value="/usr/bin/subfinder"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with respx.mock(base_url="https://crt.sh") as mock_router:
                mock_router.get("/").mock(
                    return_value=httpx.Response(200, json=[])
                )
                result = await module.run(ModuleInput(target="example.com"))

    hosts = {f.value for f in result.findings}
    assert "valid.example.com" in hosts
    assert "another.example.com" in hosts


@pytest.mark.asyncio
async def test_subfinder_not_installed_falls_back_to_crtsh(
    module: SubdomainEnumModule,
    sample_crtsh_response: list[dict],
) -> None:
    """If subfinder is not in PATH, only crt.sh is used (not an error)."""
    with patch("shutil.which", return_value=None):
        with respx.mock(base_url="https://crt.sh") as mock_router:
            mock_router.get("/").mock(
                return_value=httpx.Response(200, json=sample_crtsh_response)
            )
            result = await module.run(ModuleInput(target="example.com"))

    assert any("subfinder" in e.lower() for e in result.errors)
    assert any(f.source == "crt.sh" for f in result.findings)


@pytest.mark.asyncio
async def test_subfinder_timeout_handled(
    module: SubdomainEnumModule,
    sample_crtsh_response: list[dict],
) -> None:
    """subfinder timeout is caught; crt.sh still runs."""
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=TimeoutError())

    with patch("shutil.which", return_value="/usr/bin/subfinder"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with respx.mock(base_url="https://crt.sh") as mock_router:
                mock_router.get("/").mock(
                    return_value=httpx.Response(200, json=sample_crtsh_response)
                )
                result = await module.run(ModuleInput(target="example.com"))

    # subfinder failed but crt.sh worked
    assert any("subfinder" in e.lower() for e in result.errors)
    assert any(f.source == "crt.sh" for f in result.findings)


# ---- Dedupe ----

def test_dedupe_prefers_higher_confidence(module: SubdomainEnumModule) -> None:
    """When same subdomain is found by multiple sources, the higher-confidence one wins."""
    from app.modules.base import Finding
    from app.models import FindingType

    findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.example.com",
            source="subfinder",
            confidence=0.9,
        ),
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.example.com",
            source="crt.sh",
            confidence=0.95,
        ),
    ]
    deduped = module._dedupe(findings, "example.com")
    assert len(deduped) == 1
    assert deduped[0].source == "crt.sh"  # higher confidence wins


def test_dedupe_filters_non_matching_subdomains(module: SubdomainEnumModule) -> None:
    """Subdomains not ending with the target are filtered out."""
    from app.modules.base import Finding
    from app.models import FindingType

    findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.example.com",
            source="crt.sh",
        ),
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.other.com",
            source="crt.sh",
        ),
    ]
    deduped = module._dedupe(findings, "example.com")
    assert len(deduped) == 1
    assert deduped[0].value == "api.example.com"


def test_dedupe_case_insensitive(module: SubdomainEnumModule) -> None:
    """Dedup is case-insensitive."""
    from app.modules.base import Finding
    from app.models import FindingType

    findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            value="API.Example.com",
            source="crt.sh",
        ),
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.example.com",
            source="subfinder",
        ),
    ]
    deduped = module._dedupe(findings, "example.com")
    assert len(deduped) == 1


# ---- Metadata ----

def test_module_metadata(module: SubdomainEnumModule) -> None:
    """Module has the right Tier 1 metadata."""
    assert module.name == "subdomain_enum"
    assert module.tier.value == "tier_1"
    assert "T1596.002" in module.mitre_techniques
    assert "T1596.003" in module.mitre_techniques
    assert "T1589.001" in module.mitre_techniques
    assert module.enabled_by_default is True
    assert module.estimated_duration_seconds == 120


def test_ai_prompt_is_substantive(module: SubdomainEnumModule) -> None:
    """AI prompt has the required structure."""
    prompt = module.get_ai_prompt()
    assert "subdomain" in prompt.lower()
    assert "CONFIRMED" in prompt
    assert "FALSE_POSITIVE" in prompt
    assert "HIGH" in prompt
    assert "wildcard" in prompt.lower()  # we explicitly call this out
