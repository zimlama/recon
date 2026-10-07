"""Tests for BaseReconModule's default validate() method.

Target: lines 95, 108, 122-161 of base.py (default validate impl + abstract bodies).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.llm.schemas import (
    LDMValidationResult,
    Priority,
    RecommendedAction,
    VerdictType,
)
from app.models import FindingType, ModuleTier
from app.modules.base import BaseReconModule, Finding, ModuleInput, ModuleOutput
from app.modules.whois_rdap import WhoisRDAPModule


# ---- Concrete test module for testing default behavior ----

class _ConcreteModule(BaseReconModule):
    name = "concrete"
    description = "Concrete test module"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.002"]

    async def run(self, input: ModuleInput) -> ModuleOutput:
        return ModuleOutput(module=self.name)

    def get_ai_prompt(self) -> str:
        return "Test prompt"


# ---- Test abstract bodies (instantiation contract) ----

def test_cannot_instantiate_base_abc() -> None:
    """BaseReconModule is abstract — cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseReconModule()  # type: ignore[abstract]


def test_concrete_module_instantiable() -> None:
    """A module that implements all abstract methods can be instantiated."""
    m = _ConcreteModule()
    assert m.name == "concrete"


# ---- Test default validate() with empty findings ----

@pytest.mark.asyncio
async def test_validate_empty_findings_returns_continue() -> None:
    """Empty findings → CONTINUE with no verdicts."""
    m = _ConcreteModule()
    result = await m.validate(findings=[], target="example.com")
    assert isinstance(result, LDMValidationResult)
    assert result.verdicts == []
    assert "nothing to validate" in result.summary
    assert result.recommended_action == RecommendedAction.CONTINUE
    assert result.recommended_next_module_chain == []


# ---- Test default validate() with findings + successful LLM call ----

@pytest.mark.asyncio
async def test_validate_calls_llm_and_parses_response() -> None:
    """Default validate() calls the LLM and parses the response."""
    m = _ConcreteModule()
    findings = [
        Finding(type=FindingType.SUBDOMAIN, value="api.example.com", source="test", confidence=0.9),
    ]

    llm_response = {
        "verdicts": [
            {
                "value": "api.example.com",
                "verdict": VerdictType.CONFIRMED.value,
                "priority": Priority.HIGH.value,
                "confidence": 0.95,
                "reasoning": "Looks like a real subdomain with strong DNS evidence",
                "enrichment": {"tech": "Express"},
            }
        ],
        "summary": "Found 1 confirmed subdomain with high confidence.",
        "recommended_action": RecommendedAction.CONTINUE.value,
        "recommended_next_module_chain": ["port_scanning"],
    }

    mock_client = MagicMock()
    mock_client.chat_completion = AsyncMock(return_value=llm_response)

    result = await m.validate(findings=findings, target="example.com", llm_client=mock_client)

    # LLM was called once
    mock_client.chat_completion.assert_awaited_once()
    call_args = mock_client.chat_completion.await_args
    assert call_args.kwargs["messages"][0]["role"] == "system"
    assert call_args.kwargs["messages"][0]["content"] == "Test prompt"
    assert "example.com" in call_args.kwargs["messages"][1]["content"]
    assert "api.example.com" in call_args.kwargs["messages"][1]["content"]
    assert call_args.kwargs["response_format"] == {"type": "json_object"}
    assert call_args.kwargs["temperature"] == 0.1

    # Response was parsed
    assert "Found 1 confirmed" in result.summary
    assert result.confirmed_count == 1
    assert result.high_priority_count == 1
    assert result.recommended_next_module_chain == ["port_scanning"]


@pytest.mark.asyncio
async def test_validate_handles_llm_exception() -> None:
    """If the LLM call raises, validate() returns REQUEST_USER_DECISION."""
    m = _ConcreteModule()
    findings = [
        Finding(type=FindingType.SUBDOMAIN, value="api.example.com", source="test"),
    ]

    mock_client = MagicMock()
    mock_client.chat_completion = AsyncMock(
        side_effect=RuntimeError("LLM service unavailable"),
    )

    result = await m.validate(findings=findings, target="example.com", llm_client=mock_client)

    # On failure, REQUEST_USER_DECISION is returned
    assert result.recommended_action == RecommendedAction.REQUEST_USER_DECISION
    assert "LLM validation failed" in result.summary or "failed" in result.summary.lower()


@pytest.mark.asyncio
async def test_validate_creates_default_client_if_none() -> None:
    """If no llm_client is passed, a default one is created."""
    m = WhoisRDAPModule()  # real module
    result = await m.validate(findings=[], target="example.com")
    assert result.recommended_action == RecommendedAction.CONTINUE


@pytest.mark.asyncio
async def test_validate_uses_module_name_in_summary() -> None:
    """The summary references the module name."""
    m = _ConcreteModule()
    result = await m.validate(findings=[], target="example.com")
    assert "concrete" in result.summary


@pytest.mark.asyncio
async def test_validate_includes_findings_count_in_message() -> None:
    """The user message to the LLM includes the count of findings."""
    m = _ConcreteModule()
    findings = [
        Finding(type=FindingType.SUBDOMAIN, value=f"sub{i}.example.com", source="test")
        for i in range(3)
    ]

    mock_client = MagicMock()
    mock_client.chat_completion = AsyncMock(
        return_value={
            "verdicts": [],
            "summary": "3 subdomains found, all passive sources agree.",
            "recommended_action": "CONTINUE",
            "recommended_next_module_chain": [],
        }
    )

    await m.validate(findings=findings, target="example.com", llm_client=mock_client)

    user_message = mock_client.chat_completion.await_args.kwargs["messages"][1]["content"]
    assert "Total findings: 3" in user_message
    # Findings serialized as JSONL
    for f in findings:
        assert f.value in user_message
