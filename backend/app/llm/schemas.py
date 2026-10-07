"""Pydantic schemas for LLM structured output.

These are the contracts for what we expect the LLM to return. Use them to
validate responses from the AI before persisting to the database.
"""

from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class VerdictType(str, enum.Enum):
    """How confident we are that a finding is real + valuable."""

    CONFIRMED = "CONFIRMED"  # High confidence, in scope, actionable
    LIKELY = "LIKELY"  # Plausible but unverifiable
    SUSPECTED = "SUSPECTED"  # Data quality uncertain
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Not a real finding


class Priority(str, enum.Enum):
    """How important a finding is for the next phase."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecommendedAction(str, enum.Enum):
    """What the orchestrator should do next."""

    CONTINUE = "CONTINUE"  # Run more modules
    PRODUCE_REPORT = "PRODUCE_REPORT"  # Skip to report generation
    REQUEST_USER_DECISION = "REQUEST_USER_DECISION"  # Ask the user


class FindingVerdict(BaseModel):
    """LLM verdict on a single finding."""

    model_config = ConfigDict(extra="forbid")

    value: str = Field(..., description="The finding value (e.g., subdomain, IP, email)")
    verdict: VerdictType
    priority: Priority
    confidence: float = Field(..., ge=0.0, le=1.0, description="LLM's confidence in its verdict")
    reasoning: str = Field(..., min_length=10, description="1-2 sentence technical reasoning")
    enrichment: dict[str, str] = Field(
        default_factory=dict,
        description="Additional context (tech hints, related assets, etc.)",
    )


class LDMValidationResult(BaseModel):
    """Full LLM validation result for a module's findings."""

    model_config = ConfigDict(extra="forbid")

    verdicts: list[FindingVerdict] = Field(default_factory=list)
    summary: str = Field(..., min_length=20, description="2-3 sentence module-level summary")
    recommended_action: RecommendedAction = RecommendedAction.CONTINUE
    recommended_next_module_chain: list[str] = Field(
        default_factory=list,
        description="Module names to run next, in priority order",
    )

    @property
    def confirmed_count(self) -> int:
        """Number of CONFIRMED findings."""
        return sum(1 for v in self.verdicts if v.verdict == VerdictType.CONFIRMED)

    @property
    def likely_count(self) -> int:
        """Number of LIKELY findings."""
        return sum(1 for v in self.verdicts if v.verdict == VerdictType.LIKELY)

    @property
    def false_positive_count(self) -> int:
        """Number of FALSE_POSITIVE findings."""
        return sum(1 for v in self.verdicts if v.verdict == VerdictType.FALSE_POSITIVE)

    @property
    def suspected_count(self) -> int:
        """Number of SUSPECTED findings."""
        return sum(1 for v in self.verdicts if v.verdict == VerdictType.SUSPECTED)

    @property
    def high_priority_count(self) -> int:
        """Number of HIGH priority findings."""
        return sum(1 for v in self.verdicts if v.priority == Priority.HIGH)
