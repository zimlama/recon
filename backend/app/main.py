"""FastAPI application entrypoint.

Boots the app, registers routes, configures middleware, manages lifespan.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.audit.middleware import AuditLogMiddleware
from app.config import get_settings
from app.database import SessionLocal, init_db
from app.llm.client import LLMClient
from app.middleware import RequestIdMiddleware, RoEMiddleware
from app.modules import get_module_registry
from app.orchestrator.ai_validator import AIValidator
from app.orchestrator.job_runner import JobRunner
from app.routes import ai, findings, handoff, jobs, modules, reports

logger = structlog.get_logger(__name__)
settings = get_settings()


# ---- API key auth (closes audit finding C1) ----
# Lightweight Bearer-token gate for single-user local installs. If
# RECON_API_KEY is unset, auth is bypassed (dev mode). When set, every
# business route requires 'Authorization: Bearer <RECON_API_KEY>'.
# Health and docs routes stay open by NOT attaching this dependency to them.

async def verify_api_key(
    authorization: str | None = Header(default=None),
) -> None:
    """Validate Authorization: Bearer <RECON_API_KEY>.

    Skipped entirely when settings.RECON_API_KEY is None (dev mode).
    Returns 401 when the header is missing, malformed, or carries the wrong
    token. Reads `settings` from the module namespace on each call so tests
    can monkey-patch `main.settings` to flip auth on/off per case.
    """
    if not settings.RECON_API_KEY:
        return  # dev mode — auth disabled
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[len("Bearer "):]
    if token != settings.RECON_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


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

    # Sweep jobs stuck in VALIDATING from a previous crash.
    # Audit finding H2: a crash between `job.status = VALIDATING` and
    # `job.status = COMPLETED` would otherwise leave the job orphaned.
    # Swallow exceptions — a failed sweep must not block app startup.
    try:
        swept = await app.state.job_runner.sweep_stuck_jobs(max_age_minutes=30)
        logger.info("startup_sweep_complete", swept_jobs=swept)
    except Exception as e:  # noqa: BLE001
        logger.exception("startup_sweep_failed", error=str(e))

    logger.info("app_ready")
    yield

    # Cleanup — graceful shutdown.
    # Audit R4-H3: in-flight HTTP background jobs used to be killed
    # on `SIGTERM` because `BackgroundTasks` from FastAPI only drains
    # on response, not on shutdown. We now drain explicitly by
    # awaiting any tasks registered during the lifetime, with a 30s
    # cap so we don't hang forever on stuck work.
    logger.info("app_shutting_down")
    from app.routes.jobs import (
        drain_background_job_tasks_async,
        get_background_job_tasks,
    )

    in_flight = get_background_job_tasks()
    if in_flight:
        logger.info(
            "draining_background_tasks", count=len(in_flight)
        )
        done, pending = await drain_background_job_tasks_async(timeout=30.0)
        logger.info(
            "background_tasks_drained",
            completed=done,
            pending=pending,
        )

    if hasattr(app.state, "llm_client"):
        await app.state.llm_client.close()


def create_app() -> FastAPI:
    """Application factory."""
    # ---- CORS startup validation (fail closed) ----
    # Browsers reject responses whose Access-Control-Allow-Origin is "*"
    # when credentials are enabled. Allowing that combo silently in the
    # backend is misleading and dangerous. Refuse to boot instead.
    if "*" in settings.cors_origins_list:
        raise RuntimeError(
            "CORS misconfiguration: '*' is not a permitted value in "
            "CORS_ORIGINS when allow_credentials=True. Use an explicit "
            "allowlist of origins."
        )

    app = FastAPI(
        title="zimlama recon API",
        description="Phase 1 ethical hacking reconnaissance framework — backend API",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS middleware — explicit allowlist (no wildcard methods/headers).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    )

    # Request-ID middleware — first in the chain so downstream
    # middlewares (RoEMiddleware, AuditLog) and the response phase
    # all see the same correlation ID (audit R4-H4). Wired before
    # RoEMiddleware so a 403 carries the request_id.
    app.add_middleware(RequestIdMiddleware)

    # Rules-of-Engagement enforcement (REQ-021a, env-disabled by default).
    # Order rationale: added AFTER CORS (so pre-flight CORS requests skip
    # RoE — only POSTs are gated) and BEFORE Audit (so 403 denials are
    # still captured by the audit middleware on the way out).
    if settings.ROE_ENABLED:
        app.add_middleware(RoEMiddleware, session_factory=SessionLocal)

    # Audit middleware
    if settings.AUDIT_LOGGING_ENABLED:
        app.add_middleware(AuditLogMiddleware)

    # Routers — every business route requires API key when RECON_API_KEY is
    # set. Health, docs, openapi, and redoc endpoints (defined below) are
    # NOT included here, so they remain public.
    _auth = [Depends(verify_api_key)]
    app.include_router(jobs.router, prefix="/api/v1/jobs", tags=["jobs"], dependencies=_auth)
    app.include_router(modules.router, prefix="/api/v1/modules", tags=["modules"], dependencies=_auth)
    app.include_router(findings.router, prefix="/api/v1", tags=["findings"], dependencies=_auth)
    app.include_router(reports.router, prefix="/api/v1", tags=["reports"], dependencies=_auth)
    app.include_router(handoff.router, prefix="/api/v1", tags=["handoff"], dependencies=_auth)
    app.include_router(ai.router, prefix="/api/v1", tags=["ai"], dependencies=_auth)

    # Health endpoints — kept distinct per K8s liveness-vs-readiness semantics.
    #
    # - `/health` is the **liveness** probe: returns 200 as long as the
    #   Python process is up and the request handler dispatch works.
    #   No dependency checks. Used by Docker / Compose / K8s livenessProbe.
    #
    # - `/health/ready` is the **readiness** probe: returns 200 only if
    #   every hard dependency (DB, LLMClient construct) responds. Used by
    #   K8s readinessProbe; returns 503 if a dep is unreachable so traffic
    #   is steered away. Audit finding R4-H1 — the previous version just
    #   returned a literal 200 dict without probing anything.
    @app.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        """Liveness probe. Returns 200 if the process is up."""
        return {"status": "ok", "version": __version__}

    @app.get("/health/ready", tags=["health"])
    async def ready() -> JSONResponse:
        """Readiness probe. Returns 200 only if DB and LLMClient are OK.

        Probes:
          1. SQLAlchemy — ``SELECT 1`` against SessionLocal. Any
             SQLAlchemyError (OperationalError, DisconnectionError, …)
             returns 503.
          2. LLMClient — instantiates the client (no network IO). Surfaces
             misconfiguration (e.g. malformed MiniMax API key) at
             readiness time so K8s can steer traffic away.

        A single dependency failure is enough to mark the pod not-ready.
        """
        # 1) Database round-trip
        try:
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
        except SQLAlchemyError as exc:
            logger.error("ready_check_db_failed error=%s", exc)
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "reason": "database_unreachable",
                    "detail": "SELECT 1 failed against SessionLocal.",
                    "version": __version__,
                },
                headers={"Retry-After": "5"},
            )

        # 2) LLMClient — construct only, no network IO. Failure here
        # usually means MINIMAX_API_KEY is missing/malformed.
        try:
            LLMClient()
        except Exception as exc:  # noqa: BLE001 — readiness wants to flag all
            logger.error("ready_check_llm_failed error=%s", exc)
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "reason": "llm_client_unconstructible",
                    "detail": "LLMClient() raised at readiness check.",
                    "version": __version__,
                },
                headers={"Retry-After": "5"},
            )

        return JSONResponse(
            status_code=200,
            content={
                "status": "ready",
                "version": __version__,
                "ai_configured": str(settings.has_ai_key),
                "env": settings.APP_ENV,
            },
        )

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
