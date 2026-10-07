"""Job runner — orchestrates module execution for a recon job.

Lifecycle:
  PENDING → RUNNING → VALIDATING → COMPLETED
                              ↓
                           FAILED / CANCELLED

Per module:
  PENDING → RUNNING → COMPLETED
                    ↓
                   FAILED
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import (
    AIValidation,
    Finding as FindingModel,
    Job,
    JobStatus,
    ModuleRun,
    ModuleStatus,
)
from app.modules.base import BaseReconModule, Finding, ModuleInput, ModuleOutput
from app.orchestrator.ai_validator import AIValidator
from app.orchestrator.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class JobRunner:
    """Runs recon jobs: executes modules, persists findings, triggers AI validation."""

    def __init__(
        self,
        module_registry: dict[str, BaseReconModule],
        ai_validator: AIValidator,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.module_registry = module_registry
        self.ai_validator = ai_validator
        self.rate_limiter = rate_limiter or RateLimiter()

    async def run_job(self, job_id: str) -> None:
        """Execute a full recon job.

        1. Load job from DB
        2. Set status to RUNNING
        3. Run selected modules in parallel (asyncio.gather)
        4. After each module, trigger AI validation
        5. Generate handoff packet
        6. Set status to COMPLETED
        """
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if not job:
                raise ValueError(f"Job {job_id} not found")

            job.status = JobStatus.RUNNING
            job.started_at = datetime.utcnow()
            db.commit()
            db.refresh(job)
            target = job.target
            selected_modules = list(job.selected_modules)

        logger.info("job_started", job_id=job_id, target=target, modules=selected_modules)

        # Run modules in parallel
        module_tasks = [
            self._run_single_module(job_id, module_name, target)
            for module_name in selected_modules
            if module_name in self.module_registry
        ]
        await asyncio.gather(*module_tasks, return_exceptions=True)

        # Validate with AI
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if job and job.status == JobStatus.RUNNING:
                job.status = JobStatus.VALIDATING
                db.commit()

        await self._validate_all_modules(job_id, target)

        # Generate handoff
        try:
            from app.handoff.bridge import generate_handoff_for_job
            await generate_handoff_for_job(job_id)
        except Exception:  # noqa: BLE001
            logger.exception("handoff_generation_failed", job_id=job_id)

        # Mark complete
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if job:
                if job.status == JobStatus.VALIDATING:
                    job.status = JobStatus.COMPLETED
                job.completed_at = datetime.utcnow()
                if job.started_at:
                    job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
                db.commit()

        logger.info("job_completed", job_id=job_id, target=target)

    async def _run_single_module(
        self, job_id: str, module_name: str, target: str
    ) -> ModuleOutput | None:
        """Run a single module and persist its results."""
        module = self.module_registry.get(module_name)
        if module is None:
            logger.error("unknown_module", module=module_name)
            return None

        # Create ModuleRun record
        with SessionLocal() as db:
            module_run = ModuleRun(
                job_id=job_id,
                module_name=module_name,
                module_tier=module.tier,
                status=ModuleStatus.RUNNING,
                started_at=datetime.utcnow(),
            )
            db.add(module_run)
            db.commit()
            db.refresh(module_run)
            module_run_id = module_run.id

        # Acquire rate limit
        await self.rate_limiter.acquire(target, module_name)

        # Run the module
        start = time.time()
        try:
            output = await module.run(ModuleInput(target=target, job_id=job_id, module_run_id=module_run_id))
        except Exception as e:  # noqa: BLE001
            logger.exception("module_run_failed", module=module_name, error=str(e))
            output = ModuleOutput(
                module=module_name,
                findings=[],
                duration_seconds=time.time() - start,
                errors=[f"Module crashed: {e!s}"],
            )

        duration = time.time() - start

        # Persist findings
        with SessionLocal() as db:
            module_run = db.get(ModuleRun, module_run_id)
            if module_run:
                module_run.status = (
                    ModuleStatus.FAILED if output.errors else ModuleStatus.COMPLETED
                )
                module_run.completed_at = datetime.utcnow()
                module_run.duration_seconds = duration
                module_run.findings_count = len(output.findings)
                module_run.errors = output.errors
                module_run.raw_output_path = output.raw_output_path

                for f in output.findings:
                    db.add(
                        FindingModel(
                            module_run_id=module_run_id,
                            type=f.type,
                            value=f.value,
                            source=f.source,
                            confidence=f.confidence,
                            finding_metadata=f.finding_metadata,
                        )
                    )
                db.commit()

        return output

    async def _validate_all_modules(self, job_id: str, target: str) -> None:
        """Run AI validation on all completed module runs."""
        with SessionLocal() as db:
            module_runs = (
                db.query(ModuleRun)
                .filter(ModuleRun.job_id == job_id, ModuleRun.status == ModuleStatus.COMPLETED)
                .all()
            )
            module_run_data = [
                (mr.id, mr.module_name, [Finding(**self._finding_to_dict(f)) for f in mr.findings])
                for mr in module_runs
            ]

        for module_run_id, module_name, findings in module_run_data:
            module = self.module_registry.get(module_name)
            if module is None:
                continue

            validation = await self.ai_validator.validate_module_findings(
                module=module, target=target, findings=findings
            )

            with SessionLocal() as db:
                mr = db.get(ModuleRun, module_run_id)
                if mr and mr.validation is None:
                    db.add(
                        AIValidation(
                            module_run_id=module_run_id,
                            decision=validation.model_dump(),
                            summary=validation.summary,
                            confidence=(
                                sum(v.confidence for v in validation.verdicts)
                                / len(validation.verdicts)
                                if validation.verdicts
                                else 0.0
                            ),
                            recommended_action=validation.recommended_action.value,
                            recommended_next_modules=validation.recommended_next_module_chain,
                        )
                    )
                    db.commit()

    def _finding_to_dict(self, f: Any) -> dict[str, Any]:
        """Convert Finding ORM to dict for Pydantic Finding."""
        return {
            "type": f.type,
            "value": f.value,
            "source": f.source,
            "confidence": f.confidence,
            "finding_metadata": f.finding_metadata,
        }


__all__ = ["JobRunner"]
