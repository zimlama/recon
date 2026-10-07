"""Handoff bridge — auto-generate handoff when a job completes."""

from __future__ import annotations

import logging

from app.handoff.exporter import export_handoff

logger = logging.getLogger(__name__)


async def generate_handoff_for_job(job_id: str) -> None:
    """Generate the handoff packet for a completed job.

    Called from the JobRunner after all modules + AI validation complete.
    Idempotent — if a handoff already exists, it is regenerated.
    """
    try:
        await export_handoff(job_id)
    except Exception:  # noqa: BLE001
        logger.exception("handoff_generation_failed", job_id=job_id)


__all__ = ["generate_handoff_for_job"]
