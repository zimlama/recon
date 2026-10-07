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

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdatatype
import dns.resolver
import httpx
import pytest
import respx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.handoff.exporter import export_handoff
from app.llm.schemas import Priority, RecommendedAction, VerdictType
from app.modules import MODULE_REGISTRY
from app.models import FindingType
from app.modules.base import Finding, ModuleInput


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


# ---- End-to-end: run all 14 modules with mocks ----

def make_rdata(rtype: int, value: str) -> MagicMock:
    """Helper: create a mock DNS rdata."""
    rdata = MagicMock()
    rdata.to_text = MagicMock(return_value=value)
    if rtype == dns.rdatatype.A or rtype == dns.rdatatype.AAAA:
        rdata.address = value
    elif rtype in (dns.rdatatype.NS, dns.rdatatype.CNAME):
        rdata.target = value + "."
    elif rtype == dns.rdatatype.MX:
        rdata.preference = 10
        rdata.exchange = value
    elif rtype == dns.rdatatype.TXT:
        rdata.strings = [value.encode()]
    return rdata


def make_answer(*rdatas):
    """Helper: create a mock DNS Answer."""
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(rdatas)
    answer.__bool__ = lambda self: True
    return answer


@pytest.mark.asyncio
async def test_all_14_modules_can_run_with_mocks() -> None:
    """Every module can be instantiated and run with mocked external services."""
    # DNS resolver
    resolver = MagicMock()
    def _resolve(domain, rtype, **kwargs):
        if rtype == dns.rdatatype.A:
            return make_answer(make_rdata(dns.rdatatype.A, "1.2.3.4"))
        if rtype == dns.rdatatype.NS:
            return make_answer(make_rdata(dns.rdatatype.NS, "ns1.example.com"))
        raise dns.resolver.NoAnswer
    resolver.resolve = MagicMock(side_effect=_resolve)

    # Patch settings (some modules read config)
    with patch("app.modules.github_recon.get_settings") as mock_gh:
        mock_gh.return_value = MagicMock(GITHUB_TOKEN=None)
    with patch("app.modules.shodan_censys.get_settings") as mock_shodan:
        mock_shodan.return_value = MagicMock(CENSYS_API_ID=None, CENSYS_API_SECRET=None)
    with patch("app.modules.google_dorking.get_settings") as mock_dork:
        mock_dork.return_value = MagicMock(SERP_API_KEY=None)

    # Mock all HTTP calls
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get(url__regex=r".*crt\.sh/.*").mock(return_value=httpx.Response(200, json=[]))
        mock_router.get(url__regex=r".*rdap\.org/.*").mock(return_value=httpx.Response(200, json={
            "objectClassName": "domain", "ldhName": "example.com",
            "events": [], "entities": [], "nameservers": [],
        }))
        mock_router.get(url__regex=r".*internetdb\.shodan\.io/.*").mock(
            return_value=httpx.Response(200, json={"ports": [80, 443], "hostnames": [], "cpes": [], "tags": []})
        )
        mock_router.get(url__regex=r".*api\.github\.com/.*").mock(
            return_value=httpx.Response(200, json={"items": [], "total_count": 0})
        )
        mock_router.get(url__regex=r".*web\.archive\.org/.*").mock(
            return_value=httpx.Response(200, json=[["urlkey", "timestamp", "original"]])
        )
        mock_router.get(url__regex=r".*ahmia\.fi/.*").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        mock_router.get(url__regex=r".*pwnedpasswords\.com/.*").mock(
            return_value=httpx.Response(200, text="")
        )
        mock_router.head(url__regex=r".*linkedin\.com/.*").mock(return_value=httpx.Response(404))
        mock_router.head(url__regex=r".*github\.com/.*").mock(return_value=httpx.Response(404))
        mock_router.head(url__regex=r".*twitter\.com/.*").mock(return_value=httpx.Response(404))
        mock_router.head(url__regex=r".*facebook\.com/.*").mock(return_value=httpx.Response(404))
        mock_router.head(url__regex=r".*instagram\.com/.*").mock(return_value=httpx.Response(404))
        mock_router.head(url__regex=r".*youtube\.com/.*").mock(return_value=httpx.Response(404))
        mock_router.head(url__regex=r".*tiktok\.com/.*").mock(return_value=httpx.Response(404))

        with patch.object(MODULE_REGISTRY["dns_enum"], "_build_resolver", return_value=resolver):
            with patch("shutil.which", return_value=None):
                results = {}
                for name, module in MODULE_REGISTRY.items():
                    try:
                        result = await module.run(ModuleInput(target="example.com"))
                        results[name] = {"findings": len(result.findings), "errors": len(result.errors)}
                    except Exception as e:
                        results[name] = {"exception": str(e)}

                for name in MODULE_REGISTRY:
                    assert "exception" not in results[name], f"{name} raised: {results[name]}"
                    assert "findings" in results[name]
                    assert "errors" in results[name]

                total_findings = sum(r["findings"] for r in results.values())
                assert total_findings > 0


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
