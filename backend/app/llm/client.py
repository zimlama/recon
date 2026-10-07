"""MiniMax M3 (OpenAI-compatible) client.

Async httpx client. Supports JSON mode for structured output, retries with
exponential backoff, and graceful degradation when the API is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.config import get_settings
from app.llm.schemas import LDMValidationResult

logger = logging.getLogger(__name__)
settings = get_settings()


class LLMClient:
    """Async client for MiniMax M3 via OpenAI-compatible API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
    ) -> None:
        self.api_key = api_key or settings.MINIMAX_API_KEY
        self.base_url = (base_url or settings.MINIMAX_BASE_URL).rstrip("/")
        self.model = model or settings.MINIMAX_MODEL
        self.timeout = settings.MINIMAX_TIMEOUT_SECONDS
        self.max_retries = settings.MINIMAX_MAX_RETRIES
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init the httpx client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(self.timeout),
            )
        return self._client

    async def close(self) -> None:
        """Close the httpx client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        response_format: dict[str, str] | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        """Send a chat completion request.

        Args:
            messages: List of {role, content} messages
            response_format: e.g., {"type": "json_object"} for JSON mode
            temperature: 0.0-1.0, lower = more deterministic
            max_tokens: Max tokens in response

        Returns:
            Parsed response dict (the message content as dict, or raw if not JSON)

        Raises:
            LLMError on failure after all retries exhausted
        """
        if not self.api_key or self.api_key.startswith("sk-minimax-replace"):
            logger.warning("MINIMAX_API_KEY not configured — AI validation will be skipped")
            return self._stub_response(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format:
            payload["response_format"] = response_format

        client = await self._get_client()

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await client.post(
                    "/chat/completions",
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                parsed = self._extract_content(data)
                # Validate against LDMValidationResult schema. If the LLM
                # returned 200 OK with JSON but the shape doesn't match, we
                # surface a _malformed marker so the caller (AIValidator)
                # can decide how to handle it rather than silently producing
                # an empty/invalid result.
                try:
                    LDMValidationResult.model_validate(parsed)
                    logger.debug("llm_response_valid keys=%s", list(parsed.keys()))
                    return parsed
                except Exception as e:
                    logger.warning("llm_response_invalid_schema error=%s", str(e))
                    return {"_malformed": True, "_raw": parsed, "_error": str(e)}
            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code in (401, 403):
                    # Auth errors — don't retry
                    logger.error("LLM auth error: %s", e)
                    raise LLMError(f"Authentication failed: {e.response.status_code}") from e
                if e.response.status_code == 429:
                    # Rate limited — honor Retry-After header with jitter
                    import random
                    retry_after = e.response.headers.get("Retry-After")
                    if retry_after:
                        try:
                            wait = float(retry_after)
                        except ValueError:
                            wait = 2 ** attempt
                    else:
                        wait = 2 ** attempt
                    # Add jitter to avoid thundering herd
                    wait += random.uniform(0, 0.5 * wait)
                    logger.warning(
                        "LLM rate limited, waiting %.1fs (Retry-After: %s)",
                        wait, retry_after or "default",
                    )
                    await asyncio.sleep(wait)
                    continue
                if attempt < self.max_retries:
                    wait = 2 ** attempt
                    logger.warning("LLM HTTP %s, retry %d/%d in %ds",
                                   e.response.status_code, attempt+1, self.max_retries, wait)
                    await asyncio.sleep(wait)
                    continue
                raise LLMError(f"LLM request failed: {e}") from e
            except (httpx.RequestError, asyncio.TimeoutError) as e:
                last_error = e
                if attempt < self.max_retries:
                    wait = 2**attempt
                    logger.warning("LLM connection error, retry %d/%d in %ds",
                                   attempt+1, self.max_retries, wait)
                    await asyncio.sleep(wait)
                    continue
                raise LLMError(f"LLM connection failed: {e}") from e

        raise LLMError(f"LLM failed after {self.max_retries} retries: {last_error}")

    def _extract_content(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract the message content from the response and parse as JSON if possible."""
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"Unexpected LLM response shape: {data}") from e

        # Try to parse as JSON
        import json
        try:
            return json.loads(content)
        except (json.JSONDecodeError, TypeError):
            # Return as raw text wrapped in dict
            return {"_raw": content}

    def _stub_response(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Return a stub response when API key is not configured.

        This allows the system to run in dev/test without burning API credits.
        """
        logger.debug("Returning stub LLM response (API key not configured)")
        return {
            "verdicts": [],
            "summary": "AI validation skipped — MINIMAX_API_KEY not configured.",
            "recommended_action": "CONTINUE",
            "recommended_next_module_chain": [],
        }


class LLMError(Exception):
    """Raised when an LLM request fails after all retries."""


__all__ = ["LLMClient", "LLMError"]
