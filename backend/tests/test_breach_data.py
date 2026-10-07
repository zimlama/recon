"""Tests for the breach data module (HIBP k-anonymity)."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from app.modules.base import ModuleInput
from app.modules.breach_data import HIBP_API_URL, BreachDataModule


@pytest.fixture
def module() -> BreachDataModule:
    return BreachDataModule()


@pytest.fixture
def sample_hibp_response() -> str:
    """Sample HIBP k-anonymity response for prefix 'ABCDE'."""
    # Format: HASH_SUFFIX:BREACH_COUNT
    return """0018A45C4F5C8B2E0F1A:5
ABCDE12345:10
XYZ9999999:1"""


# ---- HIBP k-anonymity check ----

@pytest.mark.asyncio
async def test_hibp_no_breach_match(
    module: BreachDataModule,
    sample_hibp_response: str,
) -> None:
    """Email hash not in response → 0."""
    email = "test@example.com"
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest()
    prefix = sha1[:5]
    suffix = sha1[5:].upper()

    # Mock returns response that does NOT include our suffix
    response_text = f"0018A45C4F5C8B2E0F1A:5\n{prefix}NONO:1\n"
    with respx.mock(base_url="https://api.pwnedpasswords.com", assert_all_called=False) as mock:
        mock.get(f"/range/{prefix}").mock(
            return_value=httpx.Response(200, text=response_text)
        )
        count = await module._check_hibp(email)
    assert count == 0  # no match (suffix NONO doesn't match)


@pytest.mark.asyncio
async def test_hibp_breach_match(
    module: BreachDataModule,
) -> None:
    """Email hash matches a breach in HIBP → returns count."""
    email = "test@example.com"
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest()
    prefix = sha1[:5]
    suffix = sha1[5:].upper()

    # Mock response includes our suffix
    response_text = f"0018A45C4F5C8B2E0F1A:5\n{suffix}:7\n"
    with respx.mock(base_url="https://api.pwnedpasswords.com", assert_all_called=False) as mock:
        mock.get(f"/range/{prefix}").mock(
            return_value=httpx.Response(200, text=response_text)
        )
        count = await module._check_hibp(email)
    assert count == 7


@pytest.mark.asyncio
async def test_hibp_http_error_returns_zero(module: BreachDataModule) -> None:
    """HIBP HTTP error returns 0 (no breach)."""
    with respx.mock(base_url="https://api.pwnedpasswords.com", assert_all_called=False) as mock:
        mock.get(url__regex=r".*/range/.*").mock(return_value=httpx.Response(500))
        count = await module._check_hibp("test@example.com")
    assert count == 0


@pytest.mark.asyncio
async def test_hibp_connection_error_returns_zero(module: BreachDataModule) -> None:
    """HIBP connection error returns 0."""
    with respx.mock(base_url="https://api.pwnedpasswords.com", assert_all_called=False) as mock:
        mock.get(url__regex=r".*/range/.*").mock(side_effect=httpx.ConnectError("down"))
        count = await module._check_hibp("test@example.com")
    assert count == 0


@pytest.mark.asyncio
async def test_hibp_privacy_padding_header(
    module: BreachDataModule,
) -> None:
    """HIBP request includes the Add-Padding header for privacy."""
    email = "test@example.com"
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest()
    prefix = sha1[:5]

    with respx.mock(base_url="https://api.pwnedpasswords.com", assert_all_called=False) as mock:
        mock.get(url__regex=r".*/range/.*").mock(return_value=httpx.Response(200, text=""))
        await module._check_hibp(email)

        request = mock.calls[0].request
        assert "Add-Padding" in request.headers


# ---- Run ----

@pytest.mark.asyncio
async def test_run_no_emails_finds_nothing(module: BreachDataModule) -> None:
    """If no emails found, no findings are produced."""
    result = await module.run(ModuleInput(target="nonexistent.example"))
    # Either the email_harvesting call returns 0 emails, or the test target doesn't have any
    assert result.findings == []


@pytest.mark.asyncio
async def test_run_with_breaches_produces_findings(
    module: BreachDataModule,
) -> None:
    """When emails are checked and breaches found, findings are produced."""
    async def fake_get_emails(target: str) -> list[str]:
        return ["admin@example.com", "info@example.com"]

    async def fake_check_hibp(email: str) -> int:
        if "admin" in email:
            return 7
        return 0

    with patch.object(module, "_get_target_emails", side_effect=fake_get_emails):
        with patch.object(module, "_check_hibp", side_effect=fake_check_hibp):
            result = await module.run(ModuleInput(target="example.com"))

    # admin had breaches, info didn't
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert "_breaches_for_" in finding.value
    # 7 > 5 = HIGH severity
    assert finding.finding_metadata["breach_count"] == 7
    assert finding.finding_metadata["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_severity_high_for_many_breaches(module: BreachDataModule) -> None:
    """>5 breaches → severity = MEDIUM, >10 → HIGH."""
    async def fake_get_emails(target: str) -> list[str]:
        return ["admin@example.com"]

    async def fake_check_hibp(email: str) -> int:
        return 15

    with patch.object(module, "_get_target_emails", side_effect=fake_get_emails):
        with patch.object(module, "_check_hibp", side_effect=fake_check_hibp):
            result = await module.run(ModuleInput(target="example.com"))

    assert result.findings[0].finding_metadata["severity"] == "HIGH"


# ---- Metadata ----

def test_module_metadata(module: BreachDataModule) -> None:
    assert module.name == "breach_data"
    assert module.tier.value == "tier_3"
    assert module.requires_consent is True
    assert "T1589.001" in module.mitre_techniques


def test_ai_prompt_is_substantive(module: BreachDataModule) -> None:
    prompt = module.get_ai_prompt()
    assert "breach" in prompt.lower() or "HIBP" in prompt
    assert "CONFIRMED" in prompt
    assert "PRIVACY" in prompt.upper() or "credentials" in prompt.lower()


def test_dedup_emails_via_pattern(module: BreachDataModule) -> None:
    """Common email patterns are generated."""
    import asyncio
    emails = asyncio.run(module._get_target_emails("example.com"))
    assert "admin@example.com" in emails
    assert "info@example.com" in emails
    assert "noreply@example.com" in emails


def test_finding_does_not_contain_plaintext_email(module: BreachDataModule) -> None:
    """The Finding value NEVER contains the plaintext email."""
    async def fake_get_emails(target: str) -> list[str]:
        return ["sensitive.secret@example.com"]

    async def fake_check_hibp(email: str) -> int:
        return 3

    import asyncio

    async def run() -> None:
        with patch.object(module, "_get_target_emails", side_effect=fake_get_emails):
            with patch.object(module, "_check_hibp", side_effect=fake_check_hibp):
                result = await module.run(ModuleInput(target="example.com"))
        assert result.findings
        for f in result.findings:
            assert "sensitive.secret" not in f.value
            assert "sensitive.secret" not in str(f.finding_metadata)

    asyncio.run(run())