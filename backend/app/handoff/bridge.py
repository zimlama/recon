"""Handoff bridge — auto-generate handoff when a job completes."""

from __future__ import annotations

import logging

from app.handoff.exporter import export_handoff

logger = logging.getLogger(__name__)


async def generate_handoff_for_job(job_id: str) -> None:
    """Generate the handoff packet for a completed job.

    Called from the JobRunner after all modules + AI validation complete.
    Idempotent — if a handoff already exists, it is regenerated.

    Failures are recorded on the Job row (appended to error_message) so
    the operator can see that handoff generation failed, but we do NOT
    re-raise — the recon job itself succeeded, so the JobRunner will
    still mark the job COMPLETED.
    """
    try:
        await export_handoff(job_id)
        logger.info("handoff_generated job_id=%s", job_id)
    except Exception as e:  # noqa: BLE001
        logger.exception("handoff_generation_failed job_id=%s error=%s", job_id, e)
        try:
            from app.database import SessionLocal
            from app.models import Job

            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if job:
                    note = f"\nHandoff generation failed: {e!s}"
                    job.error_message = (job.error_message or "") + note
                    db.commit()
        except Exception:  # noqa: BLE001
            # Swallowing here is intentional — we already have the original
            # handoff failure logged. Don't let a secondary DB error mask it.
            logger.exception("handoff_failure_persist_failed job_id=%s", job_id)


__all__ = ["generate_handoff_for_job"]
