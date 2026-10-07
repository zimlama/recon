"""Reports routes — generate + download MD/PDF reports."""

from __future__ import annotations

from datetime import datetime
from app.models import _now
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.models import Job
from app.schemas import ReportGenerateRequest, ReportResponse
from app.utils.network import safe_filename_part

router = APIRouter()
settings = get_settings()


def _resolve_under_reports(raw_path: str, cfg: Settings) -> Path:
    """Resolve a report path and assert it lives under REPORTS_DIR.

    Guards against path traversal in stored report paths: if the path
    on the job row is absolute or contains ``..`` segments that escape
    the configured reports root, we return 403 instead of serving the
    file. Uses ``Path.is_relative_to`` (Python 3.9+) for a strict
    containment check after resolving symlinks.
    """
    reports_root = Path(cfg.REPORTS_DIR).resolve()
    resolved = Path(raw_path).resolve()
    if not resolved.is_relative_to(reports_root):
        raise HTTPException(
            status_code=403,
            detail="Forbidden",
        )
    return resolved


@router.post("/jobs/{job_id}/report", response_model=ReportResponse)
async def generate_report(
    job_id: str,
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
) -> ReportResponse:
    """Generate the MD + PDF report for a completed job."""
    from app.report.markdown_gen import MarkdownReportGenerator
    from app.report.pdf_gen import PDFGenerator

    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status.value != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Job {job_id} is not completed (status: {job.status.value})",
        )

    # Generate MD
    md_gen = MarkdownReportGenerator(db, job)
    md_path = await md_gen.generate(
        include_raw_findings=payload.include_raw_findings,
        include_ai_insights=payload.include_ai_insights,
        include_annex=payload.include_annex,
    )

    # Generate PDF (synchronous subprocess)
    pdf_gen = PDFGenerator()
    pdf_path = await pdf_gen.convert(md_path)

    # Update job
    job.report_md_path = str(md_path)
    job.report_pdf_path = str(pdf_path) if pdf_path else None
    db.commit()

    return ReportResponse(
        job_id=job_id,
        md_path=str(md_path),
        pdf_path=str(pdf_path) if pdf_path else None,
        generated_at=_now(),
    )


@router.get("/jobs/{job_id}/report/download")
async def download_report(
    job_id: str,
    format: str = "pdf",  # noqa: A002
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download the report file (md or pdf)."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    if format == "md":
        if not job.report_md_path:
            raise HTTPException(status_code=404, detail="MD report not generated yet")
        path = _resolve_under_reports(job.report_md_path, settings)
        if not path.exists():
            raise HTTPException(status_code=404, detail="MD report file not found")
        return FileResponse(
            path=path,
            media_type="text/markdown",
            filename=f"recon-{safe_filename_part(job.target)}-{job_id[:8]}.md",
        )
    elif format == "pdf":
        if not job.report_pdf_path:
            raise HTTPException(status_code=404, detail="PDF report not generated yet")
        path = _resolve_under_reports(job.report_pdf_path, settings)
        if not path.exists():
            raise HTTPException(status_code=404, detail="PDF report file not found")
        return FileResponse(
            path=path,
            media_type="application/pdf",
            filename=f"recon-{safe_filename_part(job.target)}-{job_id[:8]}.pdf",
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown format: {format}")


__all__ = ["router"]
