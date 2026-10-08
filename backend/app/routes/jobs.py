"""Jobs routes — CRUD + lifecycle for recon jobs."""

from __future__ import annotations

import asyncio
from datetime import datetime
from app.models import _now
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from sqlalchemy import desc
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models import Job, JobStatus, ModuleRun
from app.modules import MODULE_REGISTRY
from app.schemas import (
    JobCreate,
    JobListResponse,
    JobResponse,
    PaginatedResponse,
)

router = APIRouter()

# Module-level set of in-flight asyncio.Tasks. The lifespan manager
# in app/main.py reads this on shutdown so SIGTERM doesn't kill
# mid-`asyncio.gather` jobs. The set is intentionally module-level
# (not on app.state) so unit tests that bypass the lifespan can
# still drive the same drain logic.
_background_job_tasks: set[asyncio.Task] = set()


def drain_background_job_tasks(timeout: float = 30.0) -> tuple[int, int]:
    """Await every tracked background job task with a hard timeout.

    Returns ``(completed, pending)``. Used by the lifespan manager on
    SIGTERM (audit R4-H3) and by tests that need deterministic
    shutdown semantics.

    Synchronous interface for use inside an async-contextmanager —
    callers should `await drain_background_job_tasks_async(...)` if
    in an async context.
    """
    import asyncio as _asyncio

    return _asyncio.run(_drain_async(timeout))


async def drain_background_job_tasks_async(
    timeout: float = 30.0,
) -> tuple[int, int]:
    """Async form of :func:`drain_background_job_tasks`."""
    return await _drain_async(timeout)


async def _drain_async(timeout: float) -> tuple[int, int]:
    if not _background_job_tasks:
        return (0, 0)
    snapshot = list(_background_job_tasks)
    done, pending = await asyncio.wait(snapshot, timeout=timeout)
    return (len(done), len(pending))


def get_background_job_tasks() -> set[asyncio.Task]:
    """Public read-only access for tests and the lifespan manager."""
    return _background_job_tasks


@router.post("", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(
    payload: JobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Any:
    """Create a new recon job and queue it for execution.

    Validates the target format, module selection, and user consent.
    """
    # Enforce explicit user consent — required by the LATAM-aware disclaimer
    # and the project's data-residency / OSINT-ethics policy. Without it we
    # must refuse the job rather than silently store False in the DB.
    if not payload.user_consent:
        raise HTTPException(
            status_code=400,
            detail="user_consent must be true — explicit consent is required before running OSINT modules.",
        )

    # Validate modules
    for m in payload.selected_modules:
        if m not in MODULE_REGISTRY:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown module: {m}. Available: {list(MODULE_REGISTRY)}",
            )

    # Validate typed confirmation
    if payload.typed_confirmation.strip().lower() != payload.target.strip().lower():
        raise HTTPException(
            status_code=400,
            detail="Typed confirmation does not match target domain.",
        )

    # Create job
    job = Job(
        target=payload.target,
        target_type=payload.target_type,
        selected_modules=payload.selected_modules,
        user_consent=payload.user_consent,
        typed_confirmation=payload.typed_confirmation,
        consent_modal_version=payload.consent_modal_version,
        consent_timestamp=_now(),
        status=JobStatus.PENDING,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Queue execution in background. Audit R4-H3: wrap the work in an
    # asyncio.Task so the lifespan can drain it on SIGTERM (a plain
    # BackgroundTasks.add_task is fire-and-forget for the lifespan).
    task = asyncio.create_task(_run_job_background(job.id))
    _background_job_tasks.add(task)
    task.add_done_callback(_background_job_tasks.discard)
    # Also schedule via BackgroundTasks so FastAPI's response path is
    # consistent with prior versions of this route. The wrapper just
    # awaits the asyncio.Task; the actual work is already running.
    background_tasks.add_task(_await_task, task)

    return job


async def _await_task(task: asyncio.Task) -> None:  # type: ignore[type-arg]
    """FastAPI BackgroundTasks entry point.

    Await the asyncio.Task so BackgroundTasks's drain-on-response
    mechanism sees it complete. The actual work is already running
    inside ``task``; this is just a sync point for FastAPI.
    """
    try:
        await task
    except Exception:  # noqa: BLE001
        # The task already has its own error handling — silence the
        # BackgroundTasks's "exception in background task" warning.
        pass


async def _run_job_background(job_id: str) -> None:
    """Background task: execute the job."""
    from app.orchestrator.job_runner import JobRunner
    from app.llm.client import LLMClient
    from app.orchestrator.ai_validator import AIValidator

    llm_client = LLMClient()
    try:
        ai_validator = AIValidator(llm_client=llm_client)
        runner = JobRunner(
            module_registry=MODULE_REGISTRY,
            ai_validator=ai_validator,
        )
        await runner.run_job(job_id)
    finally:
        await llm_client.close()


@router.get("", response_model=PaginatedResponse[JobListResponse])
async def list_jobs(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: JobStatus | None = Query(None, alias="status"),
) -> Any:
    """List all jobs (paginated, sorted by created_at desc)."""
    query = db.query(Job)
    if status_filter:
        query = query.filter(Job.status == status_filter)

    total = query.count()
    jobs = (
        query.order_by(desc(Job.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResponse(
        items=[JobListResponse.model_validate(j) for j in jobs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size if total else 1,
    )


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: str,
    db: Session = Depends(get_db),
) -> Any:
    """Get a single job by ID, including its module runs."""
    job = (
        db.query(Job)
        .options(selectinload(Job.module_runs).selectinload(ModuleRun.findings))
        .filter(Job.id == job_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@router.post("/{job_id}/cancel", response_model=JobResponse)
async def cancel_job(
    job_id: str,
    db: Session = Depends(get_db),
) -> Any:
    """Cancel a running job (best-effort)."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
        raise HTTPException(
            status_code=400,
            detail=f"Job is already in terminal state: {job.status.value}",
        )
    job.status = JobStatus.CANCELLED
    job.completed_at = _now()
    db.commit()
    db.refresh(job)
    return job


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_job(
    job_id: str,
    db: Session = Depends(get_db),
) -> Response:
    """Delete a job and all its data (cascades to ModuleRun, Finding, AIValidation, Handoff)."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    db.delete(job)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


__all__ = ["router"]
