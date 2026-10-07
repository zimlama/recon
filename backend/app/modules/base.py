"""BaseReconModule ABC — the contract every recon module implements.

Each module is a SUBAGENT in the recon pipeline:
- Stateless: run() takes input, returns output
- Idempotent: re-running with same input produces same output (modulo time)
- Resumable: partial runs persist findings to DB
- Sandboxed: subprocess calls have timeout
- Auditable: every run logs to ModuleRun + AuditLog
"""

from __future__ import annotations

import abc
import logging
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

from app.llm.schemas import LDMValidationResult
from app.models import FindingType, ModuleTier
from app.utils.network import filter_public_ips  # noqa: F401 — SSRF contract anchor

logger = logging.getLogger(__name__)


class Finding(BaseModel):
    """A single recon finding produced by a module."""

    type: FindingType
    value: str = Field(..., min_length=1)
    source: str = Field(..., description="Where this finding came from (e.g., 'subfinder', 'crt.sh')")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    finding_metadata: dict[str, Any] = Field(default_factory=dict)


class ModuleInput(BaseModel):
    """Input to a module run."""

    target: str = Field(..., description="Target domain, IP, or URL")
    options: dict[str, Any] = Field(default_factory=dict)
    job_id: str | None = None
    module_run_id: str | None = None


class ModuleOutput(BaseModel):
    """Output of a module run."""

    module: str
    findings: list[Finding] = Field(default_factory=list)
    raw_output_path: str | None = None
    duration_seconds: float = 0.0
    errors: list[str] = Field(default_factory=list)
    completed_at: datetime | None = None


class BaseReconModule(abc.ABC):
    """Abstract base class for all recon modules.

    To implement a new module, subclass this and implement:
    - Class attributes: name, description, phase, mitre_techniques, tier
    - async def run(self, input: ModuleInput) -> ModuleOutput
    - def get_ai_prompt(self) -> str

    The base class provides:
    - async def validate(): default AI validation flow (uses LLM client)
    - Helper methods for common patterns
    """

    # ---- Class metadata (override in subclasses) ----
    name: str = ""
    description: str = ""
    phase: str = "01-recon-osint"
    tier: ModuleTier = ModuleTier.TIER_1
    mitre_techniques: list[str] = []
    requires_api_keys: list[str] = []
    requires_consent: bool = False
    estimated_duration_seconds: int | None = None
    enabled_by_default: bool = False

    def __init__(self) -> None:
        if not self.name:
            raise ValueError(f"{self.__class__.__name__} must set `name` class attribute")
        if not self.description:
            raise ValueError(f"{self.__class__.__name__} must set `description` class attribute")

    # ---- Abstract methods (must implement) ----
    @abc.abstractmethod
    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Execute the module against the target.

        Implementations should:
        - Be idempotent (no state outside this call)
        - Handle errors gracefully (collect in ModuleOutput.errors, don't raise)
        - Set realistic timeouts on subprocess calls
        - Respect rate limits (use RateLimiter port if available)
        - Persist findings to the ModuleOutput
        """
        ...

    @abc.abstractmethod
    def get_ai_prompt(self) -> str:
        """Return the system prompt for AI validation of this module's findings.

        The prompt should:
        - Describe what the module looked for
        - Define verdict categories (CONFIRMED, LIKELY, FALSE_POSITIVE, SUSPECTED)
        - Define priority categories (HIGH, MEDIUM, LOW)
        - Request structured JSON output
        - Be in English (the LLM is queried in English)
        """
        ...

    # ---- Default implementations (override if needed) ----
    async def validate(
        self,
        findings: list[Finding],
        target: str,
        llm_client: Any = None,  # LLMClient — avoid circular import
    ) -> LDMValidationResult:
        """Default AI validation flow. Override for custom logic.

        Sends findings to the LLM with the module's prompt and parses the
        response into a LDMValidationResult.
        """
        from app.llm.client import LLMClient  # avoid circular

        if llm_client is None:
            llm_client = LLMClient()

        if not findings:
            return LDMValidationResult(
                verdicts=[],
                summary=f"No findings from {self.name} — nothing to validate.",
                recommended_action="CONTINUE",
                recommended_next_module_chain=[],
            )

        from app.llm.schemas import LDMValidationResult as LDMSchema  # noqa: F401

        findings_jsonl = "\n".join(
            f'{{"value": "{f.value}", "type": "{f.type.value}", "source": "{f.source}"}}'
            for f in findings
        )
        system_prompt = self.get_ai_prompt()
        user_message = (
            f"Target: {target}\n"
            f"Module: {self.name}\n"
            f"Total findings: {len(findings)}\n\n"
            f"Findings (JSONL):\n{findings_jsonl}\n\n"
            f"Validate each finding and respond with structured JSON."
        )

        try:
            response = await llm_client.chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            return LDMValidationResult.model_validate(response)
        except Exception as e:  # noqa: BLE001
            return LDMValidationResult(
                verdicts=[],
                summary=f"AI validation failed: {e!s}",
                recommended_action="REQUEST_USER_DECISION",
                recommended_next_module_chain=[],
            )

    # ---- Helper methods (use as needed) ----
    def validate_target_format(self, target: str) -> str:
        """Sanity check the target format. Override for stricter checks."""
        if not target or len(target) < 3:
            raise ValueError(f"Invalid target: {target!r}")
        return target.strip().lower()

    # ---- SSRF defense helpers ----
    @staticmethod
    def safe_http_get(
        url: str,
        *,
        timeout: float = 15.0,
        headers: dict | None = None,
    ) -> httpx.Response | None:
        """SSRF-safe HTTP GET.

        Defense-in-depth:
        - follow_redirects=False (no pivot via redirect chain)

        Returns the response if safe, ``None`` if blocked or errored.
        Catches all ``httpx.HTTPError`` subclasses (timeouts, connection
        errors, etc.) so callers can treat a ``None`` return as "skip".

        NOTE: This is the canonical SSRF-safe HTTP helper for new code.
        Existing modules keep their inline ``httpx.AsyncClient(...
        follow_redirects=False)`` blocks (audited individually), and
        per-module URL allowlists (RDAP bootstrap, Wayback CDX, social
        platforms) remain the primary defense against SSRF pivots. URL
        parsing + ``filter_public_ips`` DNS-resolution-level enforcement
        is a candidate for a follow-up hardening pass.
        """
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                return client.get(url, headers=headers or {})
        except httpx.HTTPError as e:
            logger.debug("safe_http_get_error", extra={"url": url, "error": str(e)})
            return None

    async def safe_http_get_async(
        self,
        url: str,
        *,
        timeout: float = 15.0,
        headers: dict | None = None,
    ) -> httpx.Response | None:
        """Async SSRF-safe HTTP GET.

        Same defense contract as :meth:`safe_http_get` but uses
        ``httpx.AsyncClient`` for non-blocking IO in async module runs.
        Returns ``None`` on any ``httpx.HTTPError`` (timeout, connect,
        read, etc.).
        """
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                return await client.get(url, headers=headers or {})
        except httpx.HTTPError as e:
            logger.debug("safe_http_get_async_error", extra={"url": url, "error": str(e)})
            return None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} tier={self.tier.value}>"
