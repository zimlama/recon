"""Handoff routes — export + download handoff packets."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.handoff.exporter import export_handoff
from app.handoff.schema import HandoffPacket
from app.models import Handoff, Job
from app.schemas import HandoffResponse, PaginatedResponse
from app.utils.network import safe_filename_part

router = APIRouter()
settings = get_settings()


def _resolve_under_handoffs(raw_path: str, cfg: Settings) -> Path:
    """Resolve a handoff file path and assert it lives under HANDOFFS_DIR.

    Guards against path traversal in stored handoff paths: a crafted
    ``handoff.file_path`` (or symlink pointing outside the configured root)
    is rejected with 403 instead of being streamed back to the client.
    """
    handoffs_root = Path(cfg.HANDOFFS_DIR).resolve()
    resolved = Path(raw_path).resolve()
    if not resolved.is_relative_to(handoffs_root):
        raise HTTPException(
            status_code=403,
            detail="Forbidden",
        )
    return resolved


@router.get("/jobs/{job_id}/handoff", response_model=HandoffPacket)
async def get_job_handoff(
    job_id: str,
    db: Session = Depends(get_db),
) -> HandoffPacket:
    """Get the handoff packet for a job (as JSON, with full schema)."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    # Generate on-demand if not yet created
    handoff = db.query(Handoff).filter(Handoff.job_id == job_id).first()
    if not handoff:
        if job.status.value != "completed":
            raise HTTPException(
                status_code=400,
                detail=f"Job {job_id} not completed — handoff not available yet",
            )
        # Auto-generate
        packet = await export_handoff(job_id)
        return packet

    return HandoffPacket.model_validate(handoff.packet)


@router.get("/jobs/{job_id}/handoff/download")
async def download_handoff(
    job_id: str,
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download the handoff as a JSON file."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    handoff = db.query(Handoff).filter(Handoff.job_id == job_id).first()
    if not handoff or not handoff.file_path:
        # Auto-generate
        await export_handoff(job_id)
        db.refresh(job)
        handoff = db.query(Handoff).filter(Handoff.job_id == job_id).first()

    if not handoff or not handoff.file_path:
        raise HTTPException(status_code=500, detail="Handoff generation failed")

    path = _resolve_under_handoffs(handoff.file_path, settings)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Handoff file not found on disk")

    return FileResponse(
        path=path,
        media_type="application/json",
        filename=f"handoff-{safe_filename_part(job.target)}-{job_id[:8]}.json",
    )


@router.get("/handoffs", response_model=PaginatedResponse[HandoffResponse])
async def list_handoffs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> PaginatedResponse[HandoffResponse]:
    """List all generated handoffs (paginated)."""
    query = db.query(Handoff)
    total = query.count()
    handoffs = (
        query.order_by(desc(Handoff.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return PaginatedResponse(
        items=[HandoffResponse.model_validate(h) for h in handoffs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size if total else 1,
    )


__all__ = ["router"]
