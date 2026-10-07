"""Tests for the LLM client."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.llm.client import LLMClient, LLMError
from app.llm.schemas import LDMValidationResult, VerdictType, Priority


@pytest.mark.asyncio
async def test_stub_response_when_no_api_key() -> None:
    """When API key is not configured, return stub response."""
    client = LLMClient(api_key="sk-minimax-replace-with-real-key")
    response = await client.chat_completion(
        messages=[{"role": "user", "content": "test"}]
    )
    assert "summary" in response
    assert "AI validation skipped" in response["summary"]


@pytest.mark.asyncio
async def test_chat_completion_success() -> None:
    """chat_completion returns parsed JSON content."""
    client = LLMClient(api_key="sk-real-key", base_url="http://localhost:9999/v1")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "verdicts": [],
                        "summary": "Test summary",
                        "recommended_action": "CONTINUE",
                        "recommended_next_module_chain": [],
                    })
                }
            }
        ]
    }
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_get_client") as mock_get:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_get.return_value = mock_client

        result = await client.chat_completion(
            messages=[{"role": "user", "content": "test"}],
            response_format={"type": "json_object"},
        )

    assert result["summary"] == "Test summary"
    assert result["recommended_action"] == "CONTINUE"


@pytest.mark.asyncio
async def test_chat_completion_auth_error_no_retry() -> None:
    """Auth errors (401, 403) should raise immediately, not retry."""
    client = LLMClient(api_key="sk-bad-key", base_url="http://localhost:9999/v1", max_retries=3)

    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.raise_for_status = MagicMock(
        side_effect=__import__("httpx").HTTPStatusError(
            "401", request=MagicMock(), response=mock_response
        )
    )

    with patch.object(client, "_get_client") as mock_get:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_get.return_value = mock_client

        with pytest.raises(LLMError, match="Authentication"):
            await client.chat_completion(messages=[{"role": "user", "content": "x"}])


def test_ldm_validation_result_helpers() -> None:
    """LDMValidationResult helper properties work."""
    result = LDMValidationResult(
        verdicts=[
            {"value": "a", "verdict": VerdictType.CONFIRMED, "priority": Priority.HIGH, "confidence": 0.9, "reasoning": "a is good"},
            {"value": "b", "verdict": VerdictType.LIKELY, "priority": Priority.MEDIUM, "confidence": 0.7, "reasoning": "b is ok"},
            {"value": "c", "verdict": VerdictType.FALSE_POSITIVE, "priority": Priority.LOW, "confidence": 0.3, "reasoning": "c is bad"},
        ],
        summary="Mixed results",
        recommended_action="CONTINUE",
        recommended_next_module_chain=[],
    )
    assert result.confirmed_count == 1
    assert result.likely_count == 1
    assert result.false_positive_count == 1
    assert result.suspected_count == 0
    assert result.high_priority_count == 1
