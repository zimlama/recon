"""SQLAlchemy ORM models.

Six core entities: Job, ModuleRun, Finding, AIValidation, Handoff, AuditLog.
All have UUID v4 primary keys, created_at timestamps, JSONB/JSON metadata.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    """Generate a UUID v4 string."""
    return str(uuid.uuid4())


def _now() -> datetime:
    """Current UTC time as a naive datetime.

    Python 3.12+ deprecates `datetime.utcnow()` (naive). We use the
    timezone-aware `datetime.now(timezone.utc)` but strip tzinfo for
    SQLite storage (SQLite DateTime columns don't preserve tzinfo).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---- Enums ----

class JobStatus(str, enum.Enum):
    """Lifecycle states for a recon job."""

    PENDING = "pending"
    RUNNING = "running"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ModuleStatus(str, enum.Enum):
    """Lifecycle states for a single module execution within a job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ModuleTier(str, enum.Enum):
    """Module authorization tier. Determines when it can run."""

    TIER_1 = "tier_1"  # Always-on, fully passive
    TIER_2 = "tier_2"  # Free-tier APIs, semi-passive
    TIER_3 = "tier_3"  # White-hat gated, may be active


class FindingType(str, enum.Enum):
    """Type of a recon finding."""

    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    ASN = "asn"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    URL_HISTORICAL = "url_historical"
    URL_LIVE = "url_live"
    TECH_STACK = "tech_stack"
    DOCUMENT = "document"
    METADATA_FIELD = "metadata_field"
    SOCIAL_PROFILE = "social_profile"
    USERNAME = "username"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    DARKWEB_MENTION = "darkweb_mention"
    OTHER = "other"


class HandoffStatus(str, enum.Enum):
    """Tracks handoff packet generation status independently of the job status.

    Previously `error_message` was overloaded to carry both module errors AND
    handoff generation status. That conflated two concerns — a handoff failure
    looked indistinguishable from a module failure in the UI. This enum gives
    handoff generation its own first-class state so the operator can tell at a
    glance: "the job ran fine but the handoff failed to export".
    """

    NOT_GENERATED = "not_generated"  # Default — no handoff attempt yet
    PENDING = "pending"  # Generation in progress
    GENERATED = "generated"  # Handoff file + DB row both written
    FAILED = "failed"  # Generation attempted but raised


# ---- Models ----

class Job(Base):
    """A single recon engagement: one target, one or more modules, one report."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(20), default="domain", nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus), default=JobStatus.PENDING, nullable=False, index=True
    )

    # User consent (for audit + legal)
    user_consent: Mapped[bool] = mapped_column(default=False, nullable=False)
    consent_modal_version: Mapped[str] = mapped_column(String(20), default="v1.0")
    consent_timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    typed_confirmation: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Selected modules (JSON list of module names)
    selected_modules: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    # Lifecycle
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(nullable=True)

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Handoff generation status (independent of overall job status).
    # Index because operators filter by this to find jobs whose handoff
    # failed even though the recon itself succeeded.
    handoff_status: Mapped[str] = mapped_column(
        Enum(HandoffStatus),
        default=HandoffStatus.NOT_GENERATED,
        nullable=False,
        index=True,
    )

    # Output paths
    report_md_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    report_pdf_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Relationships
    module_runs: Mapped[list[ModuleRun]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    handoff: Mapped[Handoff | None] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
        uselist=False,
    )

    __table_args__ = (
        Index("ix_jobs_target_status", "target", "status"),
        Index("ix_jobs_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Job id={self.id} target={self.target} "
            f"status={self.status.value} handoff_status={self.handoff_status.value}>"
        )


class ModuleRun(Base):
    """A single module's execution within a job. Has its own lifecycle + findings."""

    __tablename__ = "module_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    module_name: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    module_tier: Mapped[ModuleTier] = mapped_column(
        Enum(ModuleTier), default=ModuleTier.TIER_1, nullable=False
    )
    status: Mapped[ModuleStatus] = mapped_column(
        Enum(ModuleStatus), default=ModuleStatus.PENDING, nullable=False, index=True
    )

    # Execution metadata
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(nullable=True)

    # Output
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_output_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    errors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    job: Mapped[Job] = relationship(back_populates="module_runs")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="module_run",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    validation: Mapped[AIValidation | None] = relationship(
        back_populates="module_run",
        cascade="all, delete-orphan",
        uselist=False,
    )

    __table_args__ = (
        Index("ix_module_runs_job_module", "job_id", "module_name"),
    )

    def __repr__(self) -> str:
        return f"<ModuleRun id={self.id} module={self.module_name} status={self.status.value}>"


class Finding(Base):
    """A single recon finding. May be validated by AI later."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    module_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("module_runs.id", ondelete="CASCADE"),
        nullable=False, index=True
    )

    type: Mapped[FindingType] = mapped_column(Enum(FindingType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(default=1.0, nullable=False)
    finding_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    # Relationships
    module_run: Mapped[ModuleRun] = relationship(back_populates="findings")

    __table_args__ = (
        Index("ix_findings_type_value", "type", "value"),
        # NB: `source` already gets an automatic index from `index=True` on
        # the column declaration above (which creates `ix_findings_source`).
        # Adding a duplicate explicit Index here caused
        # `OperationalError: index ix_findings_source already exists` when
        # `Base.metadata.create_all` ran in fresh sessions / test fixtures.
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} type={self.type.value} value={self.value[:50]}>"


class AIValidation(Base):
    """MiniMax M3 validation result for a module's findings."""

    __tablename__ = "ai_validations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    module_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("module_runs.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )

    # LDMDecision payload (validated by Pydantic LDMValidationResult)
    decision: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(default=0.0, nullable=False)
    recommended_action: Mapped[str] = mapped_column(String(50), nullable=False)
    recommended_next_modules: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )

    # LLM metadata
    model: Mapped[str] = mapped_column(String(100), default="MiniMax-M3", nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(nullable=True)

    validated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    # Relationships
    module_run: Mapped[ModuleRun] = relationship(back_populates="validation")

    def __repr__(self) -> str:
        return f"<AIValidation id={self.id} confidence={self.confidence:.2f}>"


class Handoff(Base):
    """Vendor-neutral handoff packet consumed by Phase 2 (future repo)."""

    __tablename__ = "handoffs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )

    schema_version: Mapped[str] = mapped_column(String(20), default="1.0.0", nullable=False)
    packet: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    # Relationships
    job: Mapped[Job] = relationship(back_populates="handoff")

    def __repr__(self) -> str:
        return f"<Handoff id={self.id} job_id={self.job_id} v{self.schema_version}>"


class AuditLog(Base):
    """Append-only audit trail. All user actions + system events."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    user_id: Mapped[str] = mapped_column(String(100), default="local", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} target={self.target}>"


# ---- Rules of Engagement (RoE) — PR 1 of v0.1.1 ----
#
# Real enforcement of scope, sign-offs, and engagement expiry. Before the
# validator approves a recon job, an operator must:
#   1. Create an RoE for the target (target + scope_type + scope_value).
#   2. Flip its status to ACTIVE.
#   3. Record at least one SignOff (and keep at least one un-revoked).
#   4. Stay inside the [valid_from, valid_until] window.
#
# The validator (see `app.orchestrator.roe`) is the single source of truth
# for "may we run a job on this target right now?".

class RoEStatus(str, enum.Enum):
    """Lifecycle of an RoE.

    - DRAFT: operator is preparing the engagement; not yet enforceable.
    - ACTIVE: validator may authorize jobs against this RoE.
    - EXPIRED: `valid_until` has passed; immutable historical record.
    - REVOKED: operator pulled the engagement; immutable historical record.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ScopeType(str, enum.Enum):
    """How the RoE's `scope_value` should be interpreted when matching a target.

    - DOMAIN: bare apex or subdomain (exact string match, case-insensitive).
    - SUBDOMAIN: pattern like ``*.example.com``; a candidate subdomain
      matches if it equals or falls under the pattern.
    - IP_RANGE: CIDR block (e.g. ``203.0.113.0/24``).
    - URL_PATTERN: glob/regex on a full URL.
    - EMPLOYEE: an individual person's identifier (email or persona_id).
    - COMPANY: a company-level scope (legal entity name or registry id).
    """

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_RANGE = "ip_range"
    URL_PATTERN = "url_pattern"
    EMPLOYEE = "employee"
    COMPANY = "company"


class RoE(Base):
    """A single Rules-of-Engagement envelope: target + scope + validity window.

    An RoE authorises recon activity against ONE target within ONE scope.
    Multiple jobs can be launched against the same RoE while it is ACTIVE
    and inside the validity window. SignOffs are stored in a separate table
    and joined via `id`.
    """

    __tablename__ = "roes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scope_type: Mapped[ScopeType] = mapped_column(Enum(ScopeType), nullable=False)
    scope_value: Mapped[str] = mapped_column(String(255), nullable=False)
    authorized_by: Mapped[str] = mapped_column(String(100), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[RoEStatus] = mapped_column(
        Enum(RoEStatus), default=RoEStatus.DRAFT, nullable=False, index=True
    )
    valid_from: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now)
    valid_until: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    # Relationship: sign-offs attached to this RoE. Cascade so deleting an
    # RoE also drops its signoffs (also enforced at the DB level via
    # ON DELETE CASCADE on `sign_offs.roe_id`). Default lazy-loading
    # (`lazy="select"`) is used instead of `selectin` because `selectin`
    # caches the relationship query per identity-map entry — once an RoE
    # is cached, any signoff added later to the same session won't be
    # visible until `expire()` is called. Callers that need eager loading
    # (the validator, the middleware) explicitly request it via
    # `selectinload(RoE.sign_offs)`.
    sign_offs: Mapped[list[SignOff]] = relationship(
        "SignOff",
        backref="roe",
        cascade="all, delete-orphan",
    )

    def is_acceptable(self, at: datetime | None = None) -> bool:
        """Return True iff `at` falls inside the validity window.

        Status checks (DRAFT / EXPIRED / REVOKED) are NOT applied here — that
        is the validator's job. Keeping this method purely date-based makes
        the model predictable and lets the validator combine `is_acceptable`
        with its own status / signoff checks.
        """
        when = at if at is not None else _now()
        return self.valid_from <= when <= self.valid_until

    def __repr__(self) -> str:
        return (
            f"<RoE id={self.id} target={self.target} "
            f"scope={self.scope_type.value}:{self.scope_value} "
            f"status={self.status.value}>"
        )


class SignOff(Base):
    """A human authorization record attached to an RoE.

    At least one SignOff with `revoked_at IS NULL` must exist for an RoE to
    be considered authorized. Revocation is recorded (not deleted) so we
    preserve audit history of who signed off and when their approval ended.
    """

    __tablename__ = "sign_offs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    roe_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("roes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    signer_name: Mapped[str] = mapped_column(String(100), nullable=False)
    signer_email: Mapped[str] = mapped_column(String(255), nullable=False)
    signer_role: Mapped[str] = mapped_column(String(100), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        revoked = "revoked" if self.revoked_at is not None else "active"
        return (
            f"<SignOff id={self.id} roe_id={self.roe_id} "
            f"signer={self.signer_email} ({revoked})>"
        )
