"""Jobs routes — CRUD + lifecycle for recon jobs."""

from __future__ import annotations

from datetime import datetime
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


@router.post("", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(
    payload: JobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Any:
    """Create a new recon job and queue it for execution.

    Validates the target format, module selection, and user consent.
    """
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
        consent_timestamp=datetime.utcnow(),
        status=JobStatus.PENDING,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Queue execution in background
    background_tasks.add_task(_run_job_background, job.id)

    return job


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
    job.completed_at = datetime.utcnow()
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
