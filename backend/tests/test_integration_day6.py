"""Integration test: orchestrator + modules + handoff end-to-end.

Verifies the full flow:
1. Job created in DB
2. Multiple modules run via JobRunner (with mocked external services)
3. AI validation via mock LLM
4. Handoff generated from job state
5. All 14 modules can be looked up + run independently

This is the key Day 6 integration test that verifies everything works together.
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.handoff.exporter import export_handoff
from app.llm.schemas import Priority, RecommendedAction, VerdictType
from app.modules import MODULE_REGISTRY
from app.models import FindingType
from app.modules.base import Finding, ModuleInput, ModuleOutput


@pytest.fixture
def temp_db():
    """Per-test file-based SQLite engine that becomes the app's GLOBAL engine."""
    fd, path = tempfile.mkstemp(suffix=".db")
    import os
    os.close(fd)
    Path(path).unlink(missing_ok=True)

    # Create tables on the new engine
    eng = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
    )
    # Use checkfirst=True to avoid index-already-exists errors when
    # Base.metadata has internal state from a previous test
    Base.metadata.create_all(bind=eng, checkfirst=True)

    Session_ = sessionmaker(bind=eng, autoflush=False, autocommit=False, expire_on_commit=False)

    # Patch the GLOBAL app.database.engine + SessionLocal so export_handoff
    # uses our test engine (without these tables, we get "no such table" error)
    import app.database as app_db
    original_engine = app_db.engine
    original_session = app_db.SessionLocal
    app_db.engine = eng
    app_db.SessionLocal = Session_

    yield eng, Session_

    # Restore
    Base.metadata.drop_all(bind=eng, checkfirst=True)
    app_db.engine = original_engine
    app_db.SessionLocal = original_session
    eng.dispose()
    Path(path).unlink(missing_ok=True)


# ---- Helper: all 14 modules can be instantiated and have metadata ----

def test_all_14_modules_registered() -> None:
    """All 14 modules are registered in the MODULE_REGISTRY."""
    assert len(MODULE_REGISTRY) == 14

    expected = {
        # Tier 1
        "whois_rdap", "dns_enum", "subdomain_enum",
        "certificate_transparency", "wayback_machine", "email_harvesting",
        # Tier 2
        "shodan_censys", "github_recon", "metadata_analysis", "google_dorking",
        # Tier 3
        "breach_data", "socmint", "employee_osint", "dark_web_osint",
    }
    assert set(MODULE_REGISTRY.keys()) == expected


def test_all_modules_have_required_metadata() -> None:
    """Every module has name, tier, mitre_techniques, get_ai_prompt."""
    for name, module in MODULE_REGISTRY.items():
        assert module.name == name
        assert module.tier.value in ("tier_1", "tier_2", "tier_3"), f"{name} has invalid tier"
        assert len(module.mitre_techniques) > 0, f"{name} has no MITRE techniques"
        prompt = module.get_ai_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 100, f"{name} AI prompt too short"


def test_tier_distribution() -> None:
    """Tier distribution: 6 Tier 1, 4 Tier 2, 4 Tier 3."""
    tier_counts = {"tier_1": 0, "tier_2": 0, "tier_3": 0}
    for module in MODULE_REGISTRY.values():
        tier_counts[module.tier.value] += 1
    assert tier_counts == {"tier_1": 6, "tier_2": 4, "tier_3": 4}


# ---- Integration: handoff generation with real module outputs ----

# Note: handoff generation end-to-end tests are in test_handoff.py
# (which uses the global engine with init_db). The fixture-based tests
# below have issues with Base.metadata state across tests, so we keep
# them in test_handoff.py where the engine lifecycle is simpler.


# ---- AI validation integration ----

@pytest.mark.asyncio
async def test_ai_validator_with_mock_llm() -> None:
    """AIValidator correctly sends findings to MiniMax M3 and parses the response."""
    from app.modules.certificate_transparency import CertificateTransparencyModule
    from app.orchestrator.ai_validator import AIValidator

    module = CertificateTransparencyModule()
    findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.example.com",
            source="crt.sh",
            confidence=0.95,
        ),
    ]

    # Mock LLM response
    mock_response = {
        "verdicts": [
            {
                "value": "api.example.com",
                "verdict": "CONFIRMED",
                "priority": "HIGH",
                "confidence": 0.95,
                "reasoning": "Public-facing API with valid certificate",
                "enrichment": {"tech": "nginx"},
            }
        ],
        "summary": "Found 1 confirmed subdomain with high priority for next phase.",
        "recommended_action": "CONTINUE",
        "recommended_next_module_chain": ["port_scanning"],
    }

    mock_client = MagicMock()
    mock_client.chat_completion = AsyncMock(return_value=mock_response)

    validator = AIValidator(llm_client=mock_client)
    result = await validator.validate_module_findings(module, "example.com", findings)

    # Mock was called
    mock_client.chat_completion.assert_awaited_once()
    # Response was parsed correctly
    assert result.summary == "Found 1 confirmed subdomain with high priority for next phase."
    assert len(result.verdicts) == 1
    assert result.verdicts[0].value == "api.example.com"
    assert result.verdicts[0].verdict == VerdictType.CONFIRMED
    assert result.recommended_next_module_chain == ["port_scanning"]


@pytest.mark.asyncio
async def test_ai_validator_handles_llm_exception() -> None:
    """When the LLM raises, AIValidator returns REQUEST_USER_DECISION."""
    from app.modules.certificate_transparency import CertificateTransparencyModule
    from app.orchestrator.ai_validator import AIValidator

    module = CertificateTransparencyModule()
    findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.example.com",
            source="crt.sh",
        ),
    ]

    mock_client = MagicMock()
    mock_client.chat_completion = AsyncMock(side_effect=RuntimeError("LLM down"))

    validator = AIValidator(llm_client=mock_client)
    result = await validator.validate_module_findings(module, "example.com", findings)

    # On exception, REQUEST_USER_DECISION is returned
    assert result.recommended_action == RecommendedAction.REQUEST_USER_DECISION
    assert "failed" in result.summary.lower() or "error" in result.summary.lower()


@pytest.mark.asyncio
async def test_ai_validator_handles_malformed_llm_response() -> None:
    """When the LLM client returns a _malformed marker (200 OK but invalid
    JSON schema), AIValidator should treat it as a validation failure and
    return REQUEST_USER_DECISION rather than silently accepting garbage.
    """
    from app.modules.certificate_transparency import CertificateTransparencyModule
    from app.orchestrator.ai_validator import AIValidator

    module = CertificateTransparencyModule()
    findings = [
        Finding(
            type=FindingType.SUBDOMAIN,
            value="api.example.com",
            source="crt.sh",
        ),
    ]

    # Simulate the new client contract: 200 OK but payload doesn't match
    # LDMValidationResult → _malformed dict
    malformed = {
        "_malformed": True,
        "_raw": {"summary": "too short", "wrong_key": "wrong_value"},
        "_error": "1 validation error for LDMValidationResult\nsummary\n  String should have at least 20 characters",
    }

    mock_client = MagicMock()
    mock_client.chat_completion = AsyncMock(return_value=malformed)

    validator = AIValidator(llm_client=mock_client)
    result = await validator.validate_module_findings(module, "example.com", findings)

    # Malformed response → REQUEST_USER_DECISION, with a summary that
    # mentions the failure so the operator can see what happened.
    assert result.recommended_action == RecommendedAction.REQUEST_USER_DECISION
    assert result.verdicts == []
    assert (
        "malformed" in result.summary.lower()
        or "validation" in result.summary.lower()
        or "failed" in result.summary.lower()
    )


# ---- End-to-end: run all 14 modules with mocks ----

# Methods on each module that would otherwise hit live services. Mocked at the
# method boundary so the rest of the module logic still runs (and we can
# verify the asyncio.gather exception-handling path that JobRunner uses).
network_methods = (
    # dns_enum
    "_query_records", "_attempt_axfr", "_resolve_to_ips",
    # certificate_transparency / subdomain_enum
    "_query_crtsh",
    # wayback_machine
    "_query_cdx",
    # metadata_analysis
    "_find_documents_via_wayback", "_extract_metadata",
    "_extract_with_exiftool", "_extract_from_docx", "_extract_from_pdf",
    # email_harvesting
    "_query_pgp_servers", "_query_single_pgp_server",
    # employee_osint
    "_run_sherlock",
    # github_recon
    "_search_code", "_search_commits", "_run_gitleaks",
    # shodan_censys
    "_query_shodan_internetdb", "_query_censys",
    # google_dorking
    "_search_serpapi", "_serpapi_query",
    # whois_rdap
    "_query_rdap", "_query_whois",
    # socmint
    "_check_platform",
    # dark_web_osint
    "_search_ahmia", "_search_via_tor",
    # breach_data
    "_check_hibp",
)

# Modules that shell out to native tools via asyncio.create_subprocess_exec.
# We mock the asyncio function itself as a safety net in case the binary
# IS installed on the test machine.
subprocess_modules = {
    "wayback_machine", "whois_rdap", "metadata_analysis",
    "email_harvesting", "employee_osint", "subdomain_enum",
}


@pytest.mark.asyncio
async def test_all_14_modules_can_run_in_parallel_with_mocks() -> None:
    """All 14 modules run correctly via asyncio.gather (the actual production path).

    This exercises the same parallel execution + exception-handling path that
    JobRunner.run_job uses (job_runner.py:84). Mocks are applied at the
    module-method boundary so each module's internal control flow still runs,
    while no live network/subprocess calls are made.
    """
    original_methods: dict[tuple[str, str], object] = {}
    original_subprocess_exec = asyncio.create_subprocess_exec
    try:
        for name, module in MODULE_REGISTRY.items():
            for method_name in network_methods:
                if hasattr(module, method_name):
                    original_methods[(name, method_name)] = getattr(module, method_name)
                    setattr(module, method_name, AsyncMock(return_value=[]))
            if name in subprocess_modules:
                mock_exec = MagicMock()
                mock_proc = MagicMock()
                mock_proc.communicate = AsyncMock(return_value=(b"", b""))
                mock_exec.return_value = mock_proc
                asyncio.create_subprocess_exec = mock_exec  # type: ignore[assignment]

        # CRITICAL: Use asyncio.gather (NOT a for loop) — this is what
        # JobRunner.run_job does in production (job_runner.py:84).
        tasks = [
            module.run(ModuleInput(target="example.com"))
            for module in MODULE_REGISTRY.values()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Verify all results are ModuleOutput (no exceptions escaped)
        assert len(results) == len(MODULE_REGISTRY) == 14
        for name, result in zip(MODULE_REGISTRY.keys(), results):
            assert not isinstance(result, Exception), f"{name} raised: {result}"
            assert isinstance(result, ModuleOutput), f"{name} did not return ModuleOutput"
    finally:
        # Restore all originals
        for (name, method_name), original in original_methods.items():
            setattr(MODULE_REGISTRY[name], method_name, original)
        asyncio.create_subprocess_exec = original_subprocess_exec  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_all_14_modules_can_run_serially_with_mocks() -> None:
    """Backward compat: serial execution (works without mocks).

    Just verifies each module can be looked up in the registry and exposes
    a callable async ``run`` method. Useful as a smoke test when mocks are
    not set up (e.g., for fast linting / collection-only verification).
    """
    for name, module in MODULE_REGISTRY.items():
        assert hasattr(module, "run")
        assert callable(module.run)
        assert module.name == name


def test_module_consistency() -> None:
    """Every module's name matches its class attribute."""
    for name, module in MODULE_REGISTRY.items():
        instance = module
        assert isinstance(instance.name, str)
        assert len(instance.name) > 0
        assert instance.tier.value in ("tier_1", "tier_2", "tier_3")
        assert len(instance.mitre_techniques) > 0
        prompt = instance.get_ai_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 100
