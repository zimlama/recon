"""AI validator — orchestrates MiniMax M3 validation for module findings."""

from __future__ import annotations

import logging
from typing import Any

from app.llm.client import LLMClient
from app.llm.prompts import get_prompt
from app.llm.schemas import LDMValidationResult
from app.modules.base import BaseReconModule, Finding

logger = logging.getLogger(__name__)


class AIValidator:
    """Validates module findings using MiniMax M3.

    Wraps the LLM client with module-specific prompts and structured output parsing.
    """

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        self.llm_client = llm_client or LLMClient()

    async def validate_module_findings(
        self,
        module: BaseReconModule,
        target: str,
        findings: list[Finding],
    ) -> LDMValidationResult:
        """Validate findings from a single module.

        Returns a parsed LDMValidationResult. On failure, returns a result
        with recommended_action=REQUEST_USER_DECISION.
        """
        if not findings:
            return LDMValidationResult(
                verdicts=[],
                summary=f"No findings from {module.name} — nothing to validate.",
                recommended_action="CONTINUE",
                recommended_next_module_chain=[],
            )

        system_prompt = get_prompt(module.name)
        findings_jsonl = "\n".join(
            f'{{"value": "{f.value}", "type": "{f.type.value}", "source": "{f.source}", "confidence": {f.confidence}}}'
            for f in findings
        )
        user_message = (
            f"Target: {target}\n"
            f"Module: {module.name}\n"
            f"Total findings: {len(findings)}\n\n"
            f"Findings (JSONL):\n{findings_jsonl}\n\n"
            f"Validate each finding and respond with structured JSON."
        )

        try:
            response = await self.llm_client.chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            return LDMValidationResult.model_validate(response)
        except Exception as e:  # noqa: BLE001
            logger.exception("AI validation failed for %s", module.name)
            return LDMValidationResult(
                verdicts=[],
                summary=f"AI validation failed: {e!s}",
                recommended_action="REQUEST_USER_DECISION",
                recommended_next_module_chain=[],
            )

    async def close(self) -> None:
        """Close the LLM client."""
        await self.llm_client.close()


__all__ = ["AIValidator"]
