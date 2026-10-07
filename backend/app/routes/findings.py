"""Findings routes — query recon findings."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models import Finding, FindingType, Job, ModuleRun
from app.schemas import FindingResponse, PaginatedResponse

router = APIRouter()


@router.get("/jobs/{job_id}/findings", response_model=PaginatedResponse[FindingResponse])
async def list_findings(
    job_id: str,
    finding_type: FindingType | None = Query(None, alias="type"),
    verdict: str | None = Query(None, description="AI verdict filter: CONFIRMED|LIKELY|SUSPECTED|FALSE_POSITIVE"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> Any:
    """List all findings for a job, with optional filters."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    query = (
        db.query(Finding)
        .join(ModuleRun, Finding.module_run_id == ModuleRun.id)
        .filter(ModuleRun.job_id == job_id)
    )
    if finding_type:
        query = query.filter(Finding.type == finding_type)
    if verdict:
        # Filter by AI verdict — requires subquery on AIValidation
        from app.models import AIValidation
        query = query.join(
            AIValidation,
            AIValidation.module_run_id == Finding.module_run_id,
        ).filter(AIValidation.decision["verdicts"].astext.contains(verdict))

    total = query.count()
    findings = query.offset((page - 1) * page_size).limit(page_size).all()

    return PaginatedResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size if total else 1,
    )


@router.get("/jobs/{job_id}/modules/{module_name}/findings", response_model=list[FindingResponse])
async def list_module_findings(
    job_id: str,
    module_name: str,
    db: Session = Depends(get_db),
) -> Any:
    """List all findings from a specific module within a job."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    module_run = (
        db.query(ModuleRun)
        .filter(ModuleRun.job_id == job_id, ModuleRun.module_name == module_name)
        .first()
    )
    if not module_run:
        raise HTTPException(
            status_code=404,
            detail=f"Module {module_name} not found for job {job_id}",
        )

    findings = (
        db.query(Finding)
        .options(selectinload(Finding.module_run))
        .filter(Finding.module_run_id == module_run.id)
        .all()
    )
    return [FindingResponse.model_validate(f) for f in findings]


__all__ = ["router"]
