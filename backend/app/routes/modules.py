"""Module catalog routes — list available recon modules."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules import MODULE_REGISTRY
from app.schemas import ModuleInfo, ModuleListResponse

router = APIRouter()


@router.get("", response_model=ModuleListResponse)
async def list_modules(
    db: Session = Depends(get_db),  # noqa: ARG001 — keep for future DB-backed catalog
) -> ModuleListResponse:
    """List all available recon modules (catalog)."""
    modules = [
        ModuleInfo(
            name=m.name,
            description=m.description,
            phase=m.phase,
            tier=m.tier,
            mitre_techniques=m.mitre_techniques,
            requires_api_keys=m.requires_api_keys,
            requires_consent=m.requires_consent,
            estimated_duration_seconds=m.estimated_duration_seconds,
            enabled_by_default=m.enabled_by_default,
        )
        for m in MODULE_REGISTRY.values()
    ]
    return ModuleListResponse(modules=modules, total=len(modules))


@router.get("/{module_name}", response_model=ModuleInfo)
async def get_module(module_name: str) -> ModuleInfo:
    """Get details for a specific module."""
    if module_name not in MODULE_REGISTRY:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown module: {module_name}. Available: {list(MODULE_REGISTRY)}",
        )
    m = MODULE_REGISTRY[module_name]
    return ModuleInfo(
        name=m.name,
        description=m.description,
        phase=m.phase,
        tier=m.tier,
        mitre_techniques=m.mitre_techniques,
        requires_api_keys=m.requires_api_keys,
        requires_consent=m.requires_consent,
        estimated_duration_seconds=m.estimated_duration_seconds,
        enabled_by_default=m.enabled_by_default,
    )


__all__ = ["router"]
