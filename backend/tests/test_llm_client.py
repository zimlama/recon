"""Tests for the LLM client (Anthropic Messages API)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.llm.client import LLMClient, LLMError
from app.llm.schemas import LDMValidationResult, Priority, VerdictType


def _text_block(text: str) -> dict:
    """Helper: build an Anthropic-format text content block."""
    return {"type": "text", "text": text}


def _thinking_block(thinking: str) -> dict:
    """Helper: build an Anthropic-format thinking content block."""
    return {"type": "thinking", "thinking": thinking}


def _anthropic_ok(text: str, extra_blocks: list[dict] | None = None) -> dict:
    """Helper: build a 200 OK Anthropic Messages response body."""
    content = []
    if extra_blocks:
        content.extend(extra_blocks)
    content.append(_text_block(text))
    return {
        "id": "msg_test123",
        "type": "message",
        "role": "assistant",
        "content": content,
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 100, "output_tokens": 50},
    }


def _anthropic_429() -> dict:
    """Helper: build a 429 rate-limit error body."""
    return {
        "type": "error",
        "error": {"type": "rate_limit_error", "message": "Too many requests"},
    }


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
    """chat_completion returns parsed JSON content (Anthropic format)."""
    client = LLMClient(api_key="sk-real-key", base_url="http://localhost:9999/v1")

    valid_json = json.dumps({
        "verdicts": [],
        "summary": "Test summary that satisfies the 20-character minimum.",
        "recommended_action": "CONTINUE",
        "recommended_next_module_chain": [],
    })
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _anthropic_ok(valid_json)
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_get_client") as mock_get:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_get.return_value = mock_client

        result = await client.chat_completion(
            messages=[{"role": "user", "content": "test"}],
        )

    assert result["recommended_action"] == "CONTINUE"
    assert "_malformed" not in result

    # Verify the request was sent to /messages with the right headers
    call_args = mock_client.post.call_args
    assert call_args[0][0] == "/messages"
    sent_payload = call_args.kwargs.get("json") or call_args[1].get("json")
    assert sent_payload["model"] == client.model
    assert "messages" in sent_payload
    assert "max_tokens" in sent_payload


@pytest.mark.asyncio
async def test_chat_completion_sends_x_api_key_header() -> None:
    """Verify the x-api-key and anthropic-version headers are configured on the client."""
    client = LLMClient(
        api_key="sk-test-key-xyz",
        base_url="http://localhost:9999/v1",
    )
    http_client = await client._get_client()
    assert http_client.headers["x-api-key"] == "sk-test-key-xyz"
    assert http_client.headers["anthropic-version"] == "2023-06-01"
    assert http_client.headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_chat_completion_ignores_thinking_blocks() -> None:
    """Thinking blocks (M3.1-Flash-Preview always emits them) must be skipped."""
    client = LLMClient(api_key="sk-real-key", base_url="http://localhost:9999/v1")

    valid_json = json.dumps({
        "verdicts": [],
        "summary": "Test summary that satisfies the 20-character minimum.",
        "recommended_action": "CONTINUE",
        "recommended_next_module_chain": [],
    })
    mock_response = MagicMock()
    mock_response.status_code = 200
    # Thinking block first, then text block
    mock_response.json.return_value = _anthropic_ok(
        valid_json,
        extra_blocks=[_thinking_block("Let me think about this carefully...")],
    )
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_get_client") as mock_get:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_get.return_value = mock_client

        result = await client.chat_completion(
            messages=[{"role": "user", "content": "test"}],
        )

    # The thinking content must not appear in the parsed result
    assert result["recommended_action"] == "CONTINUE"
    assert "_malformed" not in result


@pytest.mark.asyncio
async def test_chat_completion_extracts_system_prompt() -> None:
    """A leading system message must be sent in the top-level ``system`` field."""
    client = LLMClient(api_key="sk-real-key", base_url="http://localhost:9999/v1")

    valid_json = json.dumps({
        "verdicts": [],
        "summary": "Test summary that satisfies the 20-character minimum.",
        "recommended_action": "CONTINUE",
        "recommended_next_module_chain": [],
    })
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _anthropic_ok(valid_json)
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_get_client") as mock_get:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_get.return_value = mock_client

        await client.chat_completion(
            messages=[
                {"role": "system", "content": "You are a recon validator."},
                {"role": "user", "content": "test"},
            ],
        )

    sent_payload = mock_client.post.call_args.kwargs.get("json") or mock_client.post.call_args[1].get("json")
    assert sent_payload["system"] == "You are a recon validator."
    # System message should NOT be in the messages list
    roles = [m["role"] for m in sent_payload["messages"]]
    assert "system" not in roles
    assert roles == ["user"]


@pytest.mark.asyncio
async def test_chat_completion_malformed_response_surfaces_marker() -> None:
    """When the LLM returns 200 OK but the payload doesn't match
    LDMValidationResult (e.g. wrong keys, wrong types, summary under 20
    chars), the client surfaces a _malformed dict instead of passing raw
    junk to the validator. This is the audit-fix contract — the caller
    (AIValidator) decides what to do with malformed responses.
    """
    client = LLMClient(api_key="sk-real-key", base_url="http://localhost:9999/v1")

    mock_response = MagicMock()
    mock_response.status_code = 200
    # Wrong shape: missing 'verdicts' key, summary too short, no list
    mock_response.json.return_value = _anthropic_ok(json.dumps({
        "summary": "too short",  # < 20 chars → schema invalid
        "wrong_key": "wrong_value",
    }))
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_get_client") as mock_get:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_get.return_value = mock_client

        result = await client.chat_completion(
            messages=[{"role": "user", "content": "test"}],
        )

    assert result.get("_malformed") is True
    assert "_raw" in result
    assert "_error" in result
    assert "summary" in result["_error"].lower() or "verdict" in result["_error"].lower()


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

        # Only one call — no retry on 401
        assert mock_client.post.call_count == 1


@pytest.mark.asyncio
async def test_chat_completion_429_retries_with_backoff() -> None:
    """429 rate-limit errors should trigger a retry, then succeed."""
    client = LLMClient(api_key="sk-real-key", base_url="http://localhost:9999/v1", max_retries=2)

    # First call: 429. Second call: 200.
    rate_limit_response = MagicMock()
    rate_limit_response.status_code = 429
    rate_limit_response.headers = {"Retry-After": "0.01"}  # tiny wait for test speed
    rate_limit_response.raise_for_status = MagicMock(
        side_effect=__import__("httpx").HTTPStatusError(
            "429", request=MagicMock(), response=rate_limit_response
        )
    )

    valid_json = json.dumps({
        "verdicts": [],
        "summary": "Test summary that satisfies the 20-character minimum.",
        "recommended_action": "CONTINUE",
        "recommended_next_module_chain": [],
    })
    success_response = MagicMock()
    success_response.status_code = 200
    success_response.json.return_value = _anthropic_ok(valid_json)
    success_response.raise_for_status = MagicMock()

    with patch.object(client, "_get_client") as mock_get:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[rate_limit_response, success_response])
        mock_get.return_value = mock_client

        result = await client.chat_completion(
            messages=[{"role": "user", "content": "test"}],
        )

    assert result["recommended_action"] == "CONTINUE"
    assert mock_client.post.call_count == 2


def test_ldm_validation_result_helpers() -> None:
    """LDMValidationResult helper properties work."""
    result = LDMValidationResult(
        verdicts=[
            {"value": "a", "verdict": VerdictType.CONFIRMED, "priority": Priority.HIGH, "confidence": 0.9, "reasoning": "a is good (10+ chars)"},
            {"value": "b", "verdict": VerdictType.LIKELY, "priority": Priority.MEDIUM, "confidence": 0.7, "reasoning": "b is ok (10+ chars)"},
            {"value": "c", "verdict": VerdictType.FALSE_POSITIVE, "priority": Priority.LOW, "confidence": 0.3, "reasoning": "c is bad (10+ chars)"},
        ],
        summary="Mixed results across the three verdicts here",
        recommended_action="CONTINUE",
        recommended_next_module_chain=[],
    )
    assert result.confirmed_count == 1
    assert result.likely_count == 1
    assert result.false_positive_count == 1
    assert result.suspected_count == 0
    assert result.high_priority_count == 1
