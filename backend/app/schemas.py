"""Pydantic API schemas (request/response models).

These are distinct from SQLAlchemy ORM models in models.py — schemas are for
the HTTP API surface, ORM models are for persistence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.models import (
    FindingType,
    HandoffStatus,
    JobStatus,
    ModuleStatus,
    ModuleTier,
)

T = TypeVar("T")


# ---- Common ----

class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    detail: str | None = None
    code: str | None = None


class SuccessResponse(BaseModel):
    """Standard success response."""

    success: bool = True
    message: str | None = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response."""

    items: list[T]
    total: int
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    total_pages: int = Field(default=1, ge=1)


# ---- Job ----

class JobCreate(BaseModel):
    """Request to create a new recon job."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        ..., min_length=3, max_length=255, description="Target domain (e.g., 'example.com')"
    )
    target_type: str = Field(default="domain", pattern="^(domain|subdomain|url|ip)$")
    selected_modules: list[str] = Field(
        ...,
        min_length=1,
        max_length=14,
        description="Module names to run (max 14)",
    )
    user_consent: bool = Field(..., description="User has accepted the disclaimer")
    typed_confirmation: str = Field(
        ..., description="User must type the target domain to confirm"
    )
    consent_modal_version: str = Field(default="v1.0")


class JobResponse(BaseModel):
    """Job detail response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    target: str
    target_type: str
    status: JobStatus
    selected_modules: list[str]
    user_consent: bool
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    error_message: str | None
    handoff_status: HandoffStatus = HandoffStatus.NOT_GENERATED
    report_md_path: str | None
    report_pdf_path: str | None
    module_runs: list["ModuleRunResponse"] = []


class JobListResponse(BaseModel):
    """Job list item (lighter than JobResponse)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    target: str
    status: JobStatus
    created_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None
    selected_modules: list[str]


# ---- Module Run ----

class ModuleRunResponse(BaseModel):
    """Module run detail response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    module_name: str
    module_tier: ModuleTier
    status: ModuleStatus
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    findings_count: int
    errors: list[str]
    findings: list["FindingResponse"] = []


# ---- Finding ----

class FindingResponse(BaseModel):
    """Finding detail response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    type: FindingType
    value: str
    source: str
    confidence: float
    finding_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


# ---- Module Catalog ----

class ModuleInfo(BaseModel):
    """Module metadata (from catalog)."""

    name: str
    description: str
    phase: str
    tier: ModuleTier
    mitre_techniques: list[str]
    requires_api_keys: list[str] = Field(default_factory=list)
    requires_consent: bool = False
    estimated_duration_seconds: int | None = None
    enabled_by_default: bool = False


class ModuleListResponse(BaseModel):
    """Module catalog response."""

    modules: list[ModuleInfo]
    total: int


# ---- Handoff ----

class HandoffResponse(BaseModel):
    """Handoff packet detail response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    schema_version: str
    packet: dict[str, Any]
    file_path: str | None
    created_at: datetime


# ---- AI Validation ----

class AIValidationResponse(BaseModel):
    """AI validation detail response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    module_run_id: str
    summary: str
    confidence: float
    recommended_action: str
    recommended_next_modules: list[str]
    model: str
    total_tokens: int | None
    cost_usd: float | None
    validated_at: datetime


# ---- Report ----

class ReportGenerateRequest(BaseModel):
    """Request to generate a report for a job."""

    model_config = ConfigDict(extra="forbid")

    include_raw_findings: bool = True
    include_ai_insights: bool = True
    include_annex: bool = True


class ReportResponse(BaseModel):
    """Report metadata response."""

    job_id: str
    md_path: str | None
    pdf_path: str | None
    generated_at: datetime


# ---- Audit ----

class AuditLogResponse(BaseModel):
    """Audit log entry response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    action: str
    target: str | None
    job_id: str | None
    user_id: str
    details: dict[str, Any]


# ---- Resolve forward refs ----
JobResponse.model_rebuild()
ModuleRunResponse.model_rebuild()
