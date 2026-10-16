"""FastAPI application entrypoint.

Boots the app, registers routes, configures middleware, manages lifespan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
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


# ---- Dual-auth wrapper (sec-auth-jwt, Issue #29 PR-J3.8) --------------------
# Replaces the legacy static ``RECON_API_KEY`` Bearer gate. Accepts JWTs
# (preferred path) and falls back to the legacy static token for
# ALLOW_LEGACY_API_KEY releases per spec section 6. We import here (not
# at top of file) so the lifespan below can resolve the cycle cleanly.
from app.auth.errors import AuthError as _AuthError  # noqa: E402
from app.auth.jwt import JwtKeyManager as _JwtKeyManager  # noqa: E402
from app.auth.middleware import DualAuthMiddleware as _DualAuthMiddleware  # noqa: E402
from app.auth.refresh import RefreshService as _RefreshService  # noqa: E402


def _app_state_jwt_keys(req: Request) -> _JwtKeyManager:
    """Resolve the live JwtKeyManager from ``app.state`` for the middleware.

    The lifespan hook (``create_app`` -> ``lifespan``) populates
    ``app.state.jwt_keys`` at startup; this helper is the middleware's
    factory closure.
    """
    from app.auth.deps import get_jwt_keys

    return get_jwt_keys(req)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: init resources on startup, cleanup on shutdown."""
    # Re-read settings here so test fixtures that mutate env (e.g. via
    # get_settings.cache_clear()) are honored. The module-level
    # ``settings`` reference is frozen at first import; lifespan must
    # see the current value.
    s = get_settings()
    logger.info("app_starting", version=__version__, env=s.APP_ENV)

    # Initialize database tables
    init_db()
    logger.info("db_initialized")

    # ---- sec-auth-jwt (Issue #29, PR-J3.8) ----
    # Populate app.state with the JWT keys, the refresh service, and the
    # DB session factory the auth router depends on. We do this BEFORE
    # the LLM client init so an auth subsystem misconfig (e.g. missing
    # JWT_PRIVATE_KEY_PATH) fails the boot, not the first /auth/login.
    #
    # R4 Resilience review 2026-10-16: in APP_ENV=production any failure
    # below MUST raise RuntimeError so the orchestrator (Docker Compose /
    # K8s) restarts the pod until the operator fixes the config. In dev /
    # staging / test the failure is logged as a warning so single-user
    # local installs can still boot with zero secrets.
    is_production = s.APP_ENV == "production"

    if s.JWT_PRIVATE_KEY_PATH and s.JWT_PUBLIC_KEY_PATH:
        try:
            app.state.jwt_keys = _JwtKeyManager(
                private_path=s.JWT_PRIVATE_KEY_PATH,
                public_path=s.JWT_PUBLIC_KEY_PATH,
                kid="k1",
                issuer=s.JWT_ISSUER,
            )
            logger.info("jwt_keys_initialized")
        except Exception as exc:
            msg = f"JwtKeyManager init failed: {exc}"
            if is_production:
                # Fail the boot, not the first /auth/login (R4 + PR-J1 B-2).
                logger.error("jwt_keys_init_failed_fatal error=%s", exc)
                raise RuntimeError(
                    msg
                    + " — production deploys refuse to boot without a "
                    "working JWT subsystem. Set JWT_PRIVATE_KEY_PATH and "
                    "JWT_PUBLIC_KEY_PATH to readable RSA PEM files."
                ) from exc
            logger.warning("jwt_keys_init_failed error=%s", exc)
    elif is_production:
        raise RuntimeError(
            "JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH must both be set "
            "in production. See spec section 7 — app/auth/middleware.py "
            "DualAuthMiddleware requires a working JWT subsystem at boot."
        )

    app.state.db_session_factory = SessionLocal
    # RefreshService is only required when the auth router is actually
    # exercised. In dev/test with a 0-byte REFRESH_HASH_KEY we skip
    # construction entirely; in production a missing / too-short key is
    # also a fail-loud gate (the pydantic validator on REFRESH_HASH_KEY
    # catches empty/short in production). We belt-and-suspender it here
    # in case a non-pydantic code path ever sets a short key.
    if len(s.REFRESH_HASH_KEY) >= 32:
        try:
            app.state.refresh_service = _RefreshService(
                session_factory=SessionLocal,
                hash_key=s.REFRESH_HASH_KEY,
                refresh_ttl_seconds=s.JWT_REFRESH_TTL_SECONDS,
            )
            logger.info("refresh_service_initialized")
        except Exception as exc:
            msg = f"RefreshService init failed: {exc}"
            if is_production:
                logger.error("refresh_service_init_failed_fatal error=%s", exc)
                raise RuntimeError(
                    msg
                    + " — production deploys refuse to boot without a "
                    "working refresh-token subsystem. Set REFRESH_HASH_KEY "
                    "to a 32+ byte secret."
                ) from exc
            logger.warning("refresh_service_init_failed error=%s", exc)
    elif is_production:
        # Pydantic validator normally catches this in Settings() but be
        # explicit so future changes don't regress the fail-loud gate.
        raise RuntimeError(
            "REFRESH_HASH_KEY must be at least 32 bytes in production. "
            "See spec section 7 — RefreshService refuses to construct "
            "without a usable HMAC-SHA256 key."
        )
    else:
        logger.warning(
            "refresh_service_disabled reason=REFRESH_HASH_KEY too short"
        )

    # Initialize LLM client
    app.state.llm_client = LLMClient()
    logger.info("llm_client_initialized", has_key=s.has_ai_key)

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
    except Exception as e:
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
        logger.info("draining_background_tasks", count=len(in_flight))
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
    # Re-read settings for runtime/test mutations (env override, cache_clear).
    # If the module-level `settings` has been monkey-patched by a test
    # (e.g. test_app_wiring sets ROE_ENABLED=NotABool in env but swaps
    # `main.settings` to a valid Settings object), prefer the swap over
    # the live env read so the test's intent is honored.
    try:
        s = get_settings()
    except Exception:
        # Pydantic ValidationError (or anything else) — fall back to the
        # module-level swap if it's a valid Settings.
        import app.main as _self
        s = _self.settings
    # ---- CORS startup validation (fail closed) ----
    # Browsers reject responses whose Access-Control-Allow-Origin is "*"
    # when credentials are enabled. Allowing that combo silently in the
    # backend is misleading and dangerous. Refuse to boot instead.
    if "*" in s.cors_origins_list:
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
        allow_origins=s.cors_origins_list,
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
    if s.ROE_ENABLED:
        app.add_middleware(RoEMiddleware, session_factory=SessionLocal)

    # Audit middleware
    if s.AUDIT_LOGGING_ENABLED:
        app.add_middleware(AuditLogMiddleware)

    # Dual-auth wrapper (sec-auth-jwt, PR-J3.8). Installed LAST so it
    # sits outermost in the chain — must run before any router-level
    # guard. Replaces verify_api_key for the whole app: accepts JWTs,
    # falls back to legacy API key.
    jwt_keys_present = bool(
        s.JWT_PRIVATE_KEY_PATH and s.JWT_PUBLIC_KEY_PATH
    )
    app.add_middleware(_DualAuthMiddleware,
        jwt_keys_factory=lambda req: _app_state_jwt_keys(req),
        allow_legacy_api_key=bool(s.ALLOW_LEGACY_API_KEY),
        legacy_api_key=s.RECON_API_KEY,
        jwt_keys_configured=jwt_keys_present,
        settings_provider=get_settings,
    )

    # Routers — under the dual-auth umbrella. Health, docs, and /api/v1/auth/*
    # are intentionally NOT included so they stay public. The auth router
    # itself mounts under /api/v1/auth.
    # (No `Depends(verify_api_key)` — the dual-auth middleware already gated.)
    app.include_router(jobs.router, prefix="/api/v1/jobs", tags=["jobs"])
    app.include_router(modules.router, prefix="/api/v1/modules", tags=["modules"])
    app.include_router(findings.router, prefix="/api/v1", tags=["findings"])
    app.include_router(reports.router, prefix="/api/v1", tags=["reports"])
    app.include_router(handoff.router, prefix="/api/v1", tags=["handoff"])
    app.include_router(ai.router, prefix="/api/v1", tags=["ai"])

    # Auth router (Issue #29 PR-J3.5).
    from app.auth.router import router as auth_router
    app.include_router(auth_router)

    # Exception handler — convert AuthError subclasses into the spec'd
    # (status, headers, body) HTTP responses.
    from app.auth.errors import to_http_response as _auth_to_http

    @app.exception_handler(_AuthError)
    async def _auth_error_handler(request: Request, exc: _AuthError) -> JSONResponse:
        status, headers, body = _auth_to_http(exc)
        return JSONResponse(status_code=status, content=body, headers=headers)

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
        except Exception as exc:
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
