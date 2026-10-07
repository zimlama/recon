"""AI validation routes — trigger re-validation manually."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.llm.client import LLMClient
from app.models import AIValidation, Job, ModuleRun
from app.modules import MODULE_REGISTRY
from app.orchestrator.ai_validator import AIValidator
from app.schemas import AIValidationResponse

router = APIRouter()


@router.post("/jobs/{job_id}/validate", response_model=list[AIValidationResponse])
async def validate_job(
    job_id: str,
    db: Session = Depends(get_db),
) -> list[AIValidationResponse]:
    """Re-run AI validation for all module runs in a job."""
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    module_runs = (
        db.query(ModuleRun)
        .filter(ModuleRun.job_id == job_id)
        .all()
    )

    llm_client = LLMClient()
    try:
        validator = AIValidator(llm_client=llm_client)
        results = []
        for mr in module_runs:
            module = MODULE_REGISTRY.get(mr.module_name)
            if not module:
                continue
            from app.modules.base import Finding
            findings = [
                Finding(
                    type=f.type,
                    value=f.value,
                    source=f.source,
                    confidence=f.confidence,
                    finding_metadata=f.finding_metadata,
                )
                for f in mr.findings
            ]
            validation = await validator.validate_module_findings(module, job.target, findings)

            # Update or create AIValidation
            existing = db.query(AIValidation).filter(AIValidation.module_run_id == mr.id).first()
            if existing:
                existing.decision = validation.model_dump()
                existing.summary = validation.summary
                existing.confidence = (
                    sum(v.confidence for v in validation.verdicts) / len(validation.verdicts)
                    if validation.verdicts else 0.0
                )
                existing.recommended_action = validation.recommended_action.value
                existing.recommended_next_modules = validation.recommended_next_module_chain
            else:
                db.add(
                    AIValidation(
                        module_run_id=mr.id,
                        decision=validation.model_dump(),
                        summary=validation.summary,
                        confidence=(
                            sum(v.confidence for v in validation.verdicts) / len(validation.verdicts)
                            if validation.verdicts else 0.0
                        ),
                        recommended_action=validation.recommended_action.value,
                        recommended_next_modules=validation.recommended_next_module_chain,
                    )
                )
            db.commit()
            results.append(
                db.query(AIValidation)
                .filter(AIValidation.module_run_id == mr.id)
                .first()
            )
        return [AIValidationResponse.model_validate(r) for r in results if r is not None]
    finally:
        await llm_client.close()


@router.post("/jobs/{job_id}/modules/{module_name}/validate", response_model=AIValidationResponse)
async def validate_module(
    job_id: str,
    module_name: str,
    db: Session = Depends(get_db),
) -> AIValidationResponse:
    """Re-run AI validation for a specific module within a job."""
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

    module = MODULE_REGISTRY.get(module_name)
    if not module:
        raise HTTPException(status_code=404, detail=f"Module {module_name} not in registry")

    from app.modules.base import Finding
    findings = [
        Finding(
            type=f.type,
            value=f.value,
            source=f.source,
            confidence=f.confidence,
            finding_metadata=f.finding_metadata,
        )
        for f in module_run.findings
    ]

    llm_client = LLMClient()
    try:
        validator = AIValidator(llm_client=llm_client)
        validation = await validator.validate_module_findings(module, job.target, findings)
    finally:
        await llm_client.close()

    existing = db.query(AIValidation).filter(AIValidation.module_run_id == module_run.id).first()
    if existing:
        existing.decision = validation.model_dump()
        existing.summary = validation.summary
        existing.confidence = (
            sum(v.confidence for v in validation.verdicts) / len(validation.verdicts)
            if validation.verdicts else 0.0
        )
        existing.recommended_action = validation.recommended_action.value
        existing.recommended_next_modules = validation.recommended_next_module_chain
    else:
        existing = AIValidation(
            module_run_id=module_run.id,
            decision=validation.model_dump(),
            summary=validation.summary,
            confidence=(
                sum(v.confidence for v in validation.verdicts) / len(validation.verdicts)
                if validation.verdicts else 0.0
            ),
            recommended_action=validation.recommended_action.value,
            recommended_next_modules=validation.recommended_next_module_chain,
        )
        db.add(existing)
    db.commit()
    db.refresh(existing)
    return AIValidationResponse.model_validate(existing)


__all__ = ["router"]
