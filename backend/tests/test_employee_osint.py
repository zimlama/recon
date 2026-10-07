"""Tests for the Employee OSINT module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.modules.base import ModuleInput
from app.modules.employee_osint import EmployeeOSINTModule


@pytest.fixture
def module() -> EmployeeOSINTModule:
    return EmployeeOSINTModule()


# ---- _generate_username_patterns ----

def test_generate_username_patterns(module: EmployeeOSINTModule) -> None:
    """Username patterns are generated for the target."""
    findings = module._generate_username_patterns("acmecorp")
    # At least the org name + admin
    assert any("acmecorp" in f.value for f in findings)
    assert any("admin@acmecorp" in f.value for f in findings)
    # All marked as low confidence (unverified)
    for f in findings:
        assert f.confidence == 0.3
        assert f.finding_metadata["note"]  # has a note


# ---- _run_sherlock ----

@pytest.mark.asyncio
async def test_run_sherlock_parses_output(module: EmployeeOSINTModule) -> None:
    """Sherlock output is parsed to finding URLs."""
    stdout = b"""\
[+] Facebook: https://facebook.com/acmecorp
[+] Twitter: https://twitter.com/acmecorp
[+] Instagram: https://instagram.com/acmecorp
"""
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(stdout, b""))

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        findings = await module._run_sherlock("acmecorp")

    assert len(findings) == 3
    assert all(f.source == "sherlock" for f in findings)
    assert all("acmecorp" in f.finding_metadata.get("platform_url", "") for f in findings)


@pytest.mark.asyncio
async def test_run_sherlock_timeout_caught(module: EmployeeOSINTModule) -> None:
    """Sherlock timeout raises (caller handles via try/except)."""
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=TimeoutError())

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with pytest.raises(TimeoutError):
            await module._run_sherlock("acmecorp")


# ---- Run ----

@pytest.mark.asyncio
async def test_run_with_sherlock(module: EmployeeOSINTModule) -> None:
    """Run uses sherlock if installed + always returns pattern inferences."""
    # Mock sherlock as not installed
    stdout = b"[+] Twitter: https://twitter.com/acmecorp\n"
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(stdout, b""))

    with patch("shutil.which", return_value="/usr/bin/sherlock"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run(ModuleInput(target="acmecorp"))

    # Sherlock findings + pattern findings
    sherlock_findings = [f for f in result.findings if f.source == "sherlock"]
    pattern_findings = [f for f in result.findings if f.source == "pattern_inference"]
    assert len(sherlock_findings) == 1
    assert len(pattern_findings) >= 1


@pytest.mark.asyncio
async def test_run_without_sherlock(module: EmployeeOSINTModule) -> None:
    """Without sherlock installed, only pattern inferences are returned."""
    with patch("shutil.which", return_value=None):
        result = await module.run(ModuleInput(target="acmecorp"))

    # No sherlock findings
    assert not any(f.source == "sherlock" for f in result.findings)
    # Pattern inferences still there
    assert any(f.source == "pattern_inference" for f in result.findings)


@pytest.mark.asyncio
async def test_run_sherlock_error_logged(module: EmployeeOSINTModule) -> None:
    """If sherlock fails (exception), the error is logged but module continues."""
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=RuntimeError("sherlock crashed"))

    with patch("shutil.which", return_value="/usr/bin/sherlock"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run(ModuleInput(target="acmecorp"))

    # Error is logged
    assert any("sherlock" in e for e in result.errors)
    # Pattern inferences still returned
    assert any(f.source == "pattern_inference" for f in result.findings)


# ---- Metadata ----

def test_module_metadata(module: EmployeeOSINTModule) -> None:
    assert module.name == "employee_osint"
    assert module.tier.value == "tier_3"
    assert module.requires_consent is True


def test_ai_prompt_is_substantive(module: EmployeeOSINTModule) -> None:
    prompt = module.get_ai_prompt()
    assert "employee" in prompt.lower()
    assert "CONFIRMED" in prompt
    assert "PII" in prompt or "personal" in prompt.lower()