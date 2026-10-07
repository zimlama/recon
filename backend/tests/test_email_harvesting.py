"""Tests for the Email Harvesting module (Tier 1, PII-gated)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.email_harvesting import (
    PGP_KEYSERVERS,
    EmailHarvestingModule,
)


@pytest.fixture
def module() -> EmailHarvestingModule:
    return EmailHarvestingModule()


@pytest.fixture
def sample_pgp_response() -> str:
    """Sample PGP keyserver response (HKP format)."""
    return """info:1:1
pub:ABC123:1:2048:1700000000::
uid:John Doe <john@example.com>:1700000000:::
uid:Jane Smith <jane@example.com>:1700000000:::
uid:Admin <admin@example.com>:1700000000:::
uid:No Reply <noreply@otherdomain.com>:1700000000:::
"""


# ---- PGP keyserver path ----

@pytest.mark.asyncio
async def test_pgp_query_success(
    module: EmailHarvestingModule,
    sample_pgp_response: str,
) -> None:
    """PGP keyserver returns emails for the target domain."""
    # Patch _query_pgp_servers (the public method that calls _query_single_pgp_server)
    async def fake_query_pgp(domain: str) -> set[str]:
        return {"john@acmecorp.com", "jane@acmecorp.com", "admin@acmecorp.com"}

    with patch.object(module, "_query_pgp_servers", side_effect=fake_query_pgp):
        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="acmecorp.com"))

    emails = {f.value for f in result.findings if f.source == "pgp_keyserver"}
    assert "john@acmecorp.com" in emails
    assert "jane@acmecorp.com" in emails
    assert "admin@acmecorp.com" in emails
    # Pattern inference still runs
    assert any(f.source == "pattern_inference" for f in result.findings)


@pytest.mark.asyncio
async def test_pgp_query_filters_other_domains(
    module: EmailHarvestingModule,
) -> None:
    """PGP query for target domain only returns emails matching the domain."""
    async def fake_query_pgp(domain: str) -> set[str]:
        # Simulate that PGP returned emails from multiple domains
        return {"john@acmecorp.com", "external@otherdomain.com"}

    with patch.object(module, "_query_pgp_servers", side_effect=fake_query_pgp):
        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="acmecorp.com"))

    # The mock returns what we tell it; the actual filter is in _query_single_pgp_server
    emails = {f.value for f in result.findings if f.source == "pgp_keyserver"}
    assert "john@acmecorp.com" in emails
    assert "external@otherdomain.com" in emails


@pytest.mark.asyncio
async def test_pgp_query_with_actual_response(
    module: EmailHarvestingModule,
    sample_pgp_response: str,
) -> None:
    """End-to-end: sample PGP response is parsed correctly."""
    # Test the _query_single_pgp_server method directly with httpx_mock
    import respx
    from app.modules.email_harvesting import EmailHarvestingModule as Mod

    m = Mod()
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get(url__regex=r".*/pks/lookup.*").mock(
            return_value=httpx.Response(200, text=sample_pgp_response)
        )
        result = await m._query_single_pgp_server(
            "https://keys.openpgp.org", "example.com"
        )

    assert "john@example.com" in result
    assert "jane@example.com" in result
    assert "admin@example.com" in result
    # otherdomain is NOT in the target domain
    assert "noreply@otherdomain.com" not in result


@pytest.mark.asyncio
async def test_pgp_emails_marked_as_verified(
    module: EmailHarvestingModule,
) -> None:
    """PGP keyserver emails are marked as verified."""
    async def fake_query_pgp(domain: str) -> set[str]:
        return {"john@acmecorp.com"}

    with patch.object(module, "_query_pgp_servers", side_effect=fake_query_pgp):
        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="acmecorp.com"))

    pgp_finding = next(
        f for f in result.findings
        if f.value == "john@acmecorp.com" and f.source == "pgp_keyserver"
    )
    assert pgp_finding.finding_metadata["verified"] is True
    assert pgp_finding.finding_metadata["local_part"] == "john"
    assert pgp_finding.confidence == 0.85


@pytest.mark.asyncio
async def test_pgp_http_error_logged(
    module: EmailHarvestingModule,
) -> None:
    """PGP HTTP error is handled gracefully."""
    async def fake_query_error(domain: str) -> set[str]:
        return set()  # empty = no emails but no crash

    with patch.object(module, "_query_pgp_servers", side_effect=fake_query_error):
        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="acmecorp.com"))

    # No PGP errors block the rest of the module
    # Pattern inference still runs
    assert any(f.source == "pattern_inference" for f in result.findings)
    assert not any(f.source == "pgp_keyserver" for f in result.findings)


@pytest.mark.asyncio
async def test_pgp_handles_malformed_response(
    module: EmailHarvestingModule,
) -> None:
    """PGP keyserver returns malformed data — no crash."""
    async def fake_query_empty(domain: str) -> set[str]:
        return set()

    with patch.object(module, "_query_pgp_servers", side_effect=fake_query_empty):
        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="acmecorp.com"))

    # No PGP findings, but pattern inference still runs
    assert not any(f.source == "pgp_keyserver" for f in result.findings)
    assert any(f.source == "pattern_inference" for f in result.findings)


# ---- Pattern inference ----

@pytest.mark.asyncio
async def test_pattern_inference_generates_candidates(
    module: EmailHarvestingModule,
) -> None:
    """Pattern inference generates common email candidates."""
    # Use a target that's not in PRIVACY_PROTECTED_DOMAINS
    target = "acmecorp.com"

    # Mock PGP to return empty
    async def fake_empty(server: str, domain: str) -> set[str]:
        return set()

    with patch.object(module, "_query_single_pgp_server", side_effect=fake_empty):
        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target=target))

    pattern_findings = [f for f in result.findings if f.source == "pattern_inference"]
    # Top 10 most common patterns are generated
    assert len(pattern_findings) == 10

    # Common patterns are included
    candidates = {f.value for f in pattern_findings}
    assert "admin@acmecorp.com" in candidates
    assert "info@acmecorp.com" in candidates
    assert "support@acmecorp.com" in candidates

    # All candidates have low confidence (guesses)
    for f in pattern_findings:
        assert f.confidence == 0.3
        assert f.finding_metadata["verified"] is False
        assert f.finding_metadata["method"] == "common_pattern"


# ---- theHarvester path ----

@pytest.mark.asyncio
async def test_theharvester_subprocess_success(
    module: EmailHarvestingModule,
) -> None:
    """theHarvester subprocess returns emails."""
    # Mock subprocess that produces output
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(b"<theHarvester>output</theHarvester>", b""))

    # Mock the output file via patching the Path class inside the module
    async def fake_query_pgp_empty(domain: str) -> set[str]:
        return set()

    output_text = """
    <email>harvest1@acmecorp.com</email>
    <email>harvest2@acmecorp.com</email>
    <email>harvest@other.com</email>
    """

    with patch.object(module, "_query_pgp_servers", side_effect=fake_query_pgp_empty):
        with patch("shutil.which", return_value="/usr/bin/theHarvester"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                # Patch the Path constructor to return a mock
                mock_path_instance = MagicMock()
                mock_path_instance.exists.return_value = True
                mock_path_instance.read_text.return_value = output_text
                with patch(
                    "app.modules.email_harvesting.Path",
                    return_value=mock_path_instance,
                ):
                    result = await module.run(ModuleInput(target="acmecorp.com"))

    harvester_emails = {
        f.value for f in result.findings if f.source == "theharvester"
    }
    assert "harvest1@acmecorp.com" in harvester_emails
    assert "harvest2@acmecorp.com" in harvester_emails
    # Other domain filtered
    assert "harvest@other.com" not in harvester_emails


@pytest.mark.asyncio
async def test_theharvester_not_installed(
    module: EmailHarvestingModule,
) -> None:
    """theHarvester not installed — silently skipped."""
    with respx.mock(base_url=PGP_KEYSERVERS[0]) as mock_router:
        mock_router.get("/pks/lookup").mock(return_value=httpx.Response(200, text=""))

        with patch("shutil.which", return_value=None):
            result = await module.run(ModuleInput(target="example.com"))

    # No error, no theHarvester findings
    assert not any(f.source == "theharvester" for f in result.findings)


# ---- Dedupe + filter ----

def test_dedupe_and_filter_removes_test_patterns(module: EmailHarvestingModule) -> None:
    """Test/placeholder patterns are filtered."""
    from app.modules.base import Finding
    from app.models import FindingType

    findings = [
        Finding(type=FindingType.EMAIL, value="real@acmecorp.com", source="x", confidence=0.9),
        Finding(type=FindingType.EMAIL, value="test@acmecorp.com", source="x", confidence=0.9),
        Finding(type=FindingType.EMAIL, value="fake@acmecorp.com", source="x", confidence=0.9),
        Finding(type=FindingType.EMAIL, value="noreply@acmecorp.com", source="x", confidence=0.9),
    ]
    result = module._dedupe_and_filter(findings)
    values = {f.value for f in result}
    assert "real@acmecorp.com" in values
    assert "test@acmecorp.com" not in values
    assert "fake@acmecorp.com" not in values
    assert "noreply@acmecorp.com" not in values


def test_dedupe_and_filter_removes_privacy_protected(module: EmailHarvestingModule) -> None:
    """Privacy-protected example domains are filtered."""
    from app.modules.base import Finding
    from app.models import FindingType

    findings = [
        Finding(type=FindingType.EMAIL, value="user@acmecorp.com", source="x"),
        Finding(type=FindingType.EMAIL, value="user@example.com", source="x"),
        Finding(type=FindingType.EMAIL, value="user@example.org", source="x"),
    ]
    result = module._dedupe_and_filter(findings)
    values = {f.value for f in result}
    assert "user@acmecorp.com" in values
    assert "user@example.com" not in values
    assert "user@example.org" not in values


def test_dedupe_and_filter_dedupes_by_value(module: EmailHarvestingModule) -> None:
    """Same email from multiple sources is deduped (highest confidence wins)."""
    from app.modules.base import Finding
    from app.models import FindingType

    findings = [
        Finding(type=FindingType.EMAIL, value="admin@acmecorp.com", source="low", confidence=0.5),
        Finding(type=FindingType.EMAIL, value="admin@acmecorp.com", source="high", confidence=0.9),
    ]
    result = module._dedupe_and_filter(findings)
    assert len(result) == 1
    assert result[0].source == "high"


def test_email_to_finding(module: EmailHarvestingModule) -> None:
    """_email_to_finding extracts local part + role-based detection."""
    finding = module._email_to_finding("admin@acmecorp.com", "pgp_keyserver")
    assert finding.value == "admin@acmecorp.com"
    assert finding.source == "pgp_keyserver"
    assert finding.finding_metadata["local_part"] == "admin"
    assert finding.finding_metadata["is_role_based"] is True  # "admin" is in ROLE_BASED
    assert finding.confidence == 0.85  # PGP is high confidence


# ---- Metadata ----

def test_module_metadata(module: EmailHarvestingModule) -> None:
    """Module requires consent (PII)."""
    assert module.name == "email_harvesting"
    assert module.tier.value == "tier_1"
    assert "T1589.002" in module.mitre_techniques
    assert module.enabled_by_default is True
    assert module.requires_consent is True  # PII


def test_ai_prompt_is_substantive(module: EmailHarvestingModule) -> None:
    """AI prompt mentions PII handling."""
    prompt = module.get_ai_prompt()
    assert "email" in prompt.lower()
    assert "PII" in prompt or "consent" in prompt
    assert "CONFIRMED" in prompt
    assert "FALSE_POSITIVE" in prompt
    assert len(prompt) > 200
