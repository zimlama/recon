"""FastAPI application entrypoint.

Boots the app, registers routes, configures middleware, manages lifespan.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.audit.middleware import AuditLogMiddleware
from app.config import get_settings
from app.database import init_db
from app.llm.client import LLMClient
from app.modules import get_module_registry
from app.orchestrator.ai_validator import AIValidator
from app.orchestrator.job_runner import JobRunner
from app.routes import ai, findings, handoff, jobs, modules, reports

logger = structlog.get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: init resources on startup, cleanup on shutdown."""
    logger.info("app_starting", version=__version__, env=settings.APP_ENV)

    # Initialize database tables
    init_db()
    logger.info("db_initialized")

    # Initialize LLM client
    app.state.llm_client = LLMClient()
    logger.info("llm_client_initialized", has_key=settings.has_ai_key)

    # Initialize AI validator + job runner
    app.state.ai_validator = AIValidator(llm_client=app.state.llm_client)
    app.state.job_runner = JobRunner(
        module_registry=get_module_registry(),
        ai_validator=app.state.ai_validator,
    )
    logger.info("orchestrator_initialized", modules=len(get_module_registry()))

    logger.info("app_ready")
    yield

    # Cleanup
    logger.info("app_shutting_down")
    if hasattr(app.state, "llm_client"):
        await app.state.llm_client.close()


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="zimlama recon API",
        description="Phase 1 ethical hacking reconnaissance framework — backend API",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Audit middleware
    if settings.AUDIT_LOGGING_ENABLED:
        app.add_middleware(AuditLogMiddleware)

    # Routers
    app.include_router(jobs.router, prefix="/api/v1/jobs", tags=["jobs"])
    app.include_router(modules.router, prefix="/api/v1/modules", tags=["modules"])
    app.include_router(findings.router, prefix="/api/v1", tags=["findings"])
    app.include_router(reports.router, prefix="/api/v1", tags=["reports"])
    app.include_router(handoff.router, prefix="/api/v1", tags=["handoff"])
    app.include_router(ai.router, prefix="/api/v1", tags=["ai"])

    # Health endpoints
    @app.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        """Liveness probe. Returns 200 if the process is up."""
        return {"status": "ok", "version": __version__}

    @app.get("/health/ready", tags=["health"])
    async def ready() -> dict[str, str]:
        """Readiness probe. Returns 200 if all dependencies are ready."""
        return {
            "status": "ready",
            "version": __version__,
            "ai_configured": str(settings.has_ai_key),
            "env": settings.APP_ENV,
        }

    @app.get("/", tags=["root"])
    async def root() -> dict[str, str]:
        """Root endpoint. Returns service info."""
        return {
            "service": "zimlama-recon",
            "version": __version__,
            "docs": "/docs",
            "health": "/health",
        }

    return app


app = create_app()
