"""MiniMax M3.1-Flash-Preview (Anthropic Messages API) client.

Async httpx client targeting MiniMax's Anthropic-compatible endpoint at
https://api.minimax.io/anthropic/v1/messages.

Notes on the protocol:
- Auth uses ``x-api-key`` header (NOT ``Authorization: Bearer``). MiniMax
  server-side explicitly checks for the ``X-Api-Key`` field per its error
  message: "Please carry the API secret key in the 'X-Api-Key' field of
  the request header".
- The Anthropic Messages API has no native JSON mode flag. JSON mode is
  enforced via the system prompt, which is sent as a separate top-level
  ``system`` field (NOT as ``messages[0].role="system"``).
- The M3.1-Flash-Preview model always emits a ``thinking`` content block
  before the ``text`` block. We ignore ``thinking`` blocks in our
  single-shot AI validation path (no multi-turn state to preserve).
- Supports retries with exponential backoff + jitter on 429/5xx. Auth
  errors (401/403) raise immediately.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from app.config import get_settings
from app.llm.schemas import LDMValidationResult

logger = logging.getLogger(__name__)
settings = get_settings()


# MiniMax Anthropic-compatible API version (per Anthropic SDK convention)
ANTHROPIC_API_VERSION = "2023-06-01"


class LLMClient:
    """Async client for MiniMax M3.1-Flash-Preview via the Anthropic Messages API.

    The same client also works against any Anthropic-compatible endpoint
    (the Anthropic API directly, or a local gateway) by overriding
    ``MINIMAX_BASE_URL`` and ``MINIMAX_API_KEY``.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        max_retries: int = 3,
    ) -> None:
        self.api_key = api_key or settings.MINIMAX_API_KEY
        self.base_url = (base_url or settings.MINIMAX_BASE_URL).rstrip("/")
        self.model = model or settings.MINIMAX_MODEL
        self.timeout = settings.MINIMAX_TIMEOUT_SECONDS
        # Allow caller override (default 3) for tests/REPL. Settings value is
        # still used as the fallback via the default value.
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init the httpx client with Anthropic-compatible headers."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": ANTHROPIC_API_VERSION,
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

    async def chat_completion(  # noqa: C901 - complexity 14, refactor tracked in issue #43
        self,
        messages: list[dict[str, str]],
        response_format: dict[str, str] | None = None,  # accepted for back-compat; ignored
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        """Send a messages request to the Anthropic-compatible endpoint.

        Args:
            messages: List of ``{role, content}`` messages. The Anthropic
                Messages API expects alternating ``user`` / ``assistant``
                roles. Any system message is extracted and sent via the
                top-level ``system`` field instead of in ``messages``.
            response_format: Accepted for back-compat with the previous
                OpenAI-based client. **Ignored** — the Anthropic Messages
                API has no native JSON mode. JSON enforcement comes from
                the system prompt (see ``backend/app/llm/prompts.py``).
            temperature: 0.0-1.0 for M3.x (Anthropic range is 0-2). Lower
                = more deterministic.
            max_tokens: Max tokens to generate. Note: for
                M3.1-Flash-Preview, *thinking* tokens count toward this
                limit, so a too-low value yields ``stop_reason:
                max_tokens`` with no text output.

        Returns:
            Parsed response dict (the message content as dict, or raw if
            not JSON). When the LLM returns 200 OK with JSON but the
            shape doesn't match ``LDMValidationResult``, surfaces a
            ``_malformed`` marker so the caller (AIValidator) can decide.

        Raises:
            LLMError on failure after all retries exhausted.
        """
        if not self.api_key or self.api_key.startswith("sk-minimax-replace"):
            logger.warning("MINIMAX_API_KEY not configured — AI validation will be skipped")
            return self._stub_response(messages)

        system, user_messages = self._split_system(messages)

        # Per MiniMax docs: the API accepts both dict and string content
        # for the user role. We pass strings as-is (the standard form).
        anthropic_messages: list[dict[str, Any]] = []
        for m in user_messages:
            anthropic_messages.append(
                {
                    "role": m["role"],
                    "content": m["content"],
                }
            )

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": anthropic_messages,
        }
        if system:
            payload["system"] = system

        client = await self._get_client()

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await client.post(
                    "/messages",
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
                            wait = 2**attempt
                    else:
                        wait = 2**attempt
                    # Add jitter to avoid thundering herd
                    wait += random.uniform(0, 0.5 * wait)
                    logger.warning(
                        "LLM rate limited, waiting %.1fs (Retry-After: %s)",
                        wait,
                        retry_after or "default",
                    )
                    await asyncio.sleep(wait)
                    continue
                if attempt < self.max_retries:
                    wait = 2**attempt
                    logger.warning(
                        "LLM HTTP %s, retry %d/%d in %ds",
                        e.response.status_code,
                        attempt + 1,
                        self.max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise LLMError(f"LLM request failed: {e}") from e
            except (TimeoutError, httpx.RequestError) as e:
                last_error = e
                if attempt < self.max_retries:
                    wait = 2**attempt
                    logger.warning(
                        "LLM connection error, retry %d/%d in %ds",
                        attempt + 1,
                        self.max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise LLMError(f"LLM connection failed: {e}") from e

        raise LLMError(f"LLM failed after {self.max_retries} retries: {last_error}")

    @staticmethod
    def _split_system(
        messages: list[dict[str, str]],
    ) -> tuple[str, list[dict[str, str]]]:
        """Separate a leading ``system`` message from user/assistant turns.

        The Anthropic Messages API wants the system prompt in a top-level
        ``system`` field, NOT in ``messages[0]``. If a caller passes a
        list starting with ``role="system"`` (the OpenAI convention), we
        extract it and pass the rest as the messages list.
        """
        if not messages:
            return "", []
        if messages[0].get("role") == "system":
            return messages[0].get("content", ""), messages[1:]
        return "", list(messages)

    def _extract_content(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract the text content from an Anthropic Messages response.

        Skips ``thinking`` blocks (M3.1-Flash-Preview always emits them).
        If multiple ``text`` blocks are present, they are concatenated.
        """
        try:
            content_blocks = data["content"]
        except (KeyError, TypeError) as e:
            raise LLMError(f"Unexpected LLM response shape: {data}") from e

        text_parts: list[str] = []
        for block in content_blocks:
            # Only read text blocks. thinking/tool_use blocks are ignored
            # for our single-shot validation; in a multi-turn conversation
            # they would need to be preserved in the message history.
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))

        text = "".join(text_parts)
        if not text:
            # Model returned only thinking blocks, or empty content.
            return {"_raw": text}

        # Try to parse as JSON
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            # Return as raw text wrapped in dict
            return {"_raw": text}

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
