"""Audit log middleware — logs all requests to AuditLog table.

sec-auth-jwt (Issue #29 PR-J3.7): the middleware now reads
``request.state.user_id``, ``request.state.username`` and
``request.state.jwt_jti`` populated by ``app.auth.middleware.DualAuthMiddleware``
so audit rows carry the authenticated principal instead of the legacy
hardcoded ``user_id='local'`` fallback.

The fallback to ``"local"`` is preserved for endpoints that bypass auth
(``/health``, ``/health/ready``, ``/docs``, ``/openapi.json``,
``/redoc``, ``/favicon.ico`` and the ``/api/v1/auth/*`` auth lifecycle
endpoints the dual-auth middleware itself keeps open). The audit row
type stays distinguishable — ``username='local'`` means unauthenticated
bypass, ``username='legacy'`` means Bearer-key legacy path.
"""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import SessionLocal
from app.models import AuditLog


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Log every API request to the AuditLog table.

    Captures: timestamp, action, target (from path/query), job_id (if present),
    user_id, username, request_jwt_jti, details (method, path, status_code, duration).

    Auth context is read from ``request.state`` populated by upstream
    middleware (DualAuthMiddleware). Endpoints that bypass auth fall
    through to the ``"local"`` placeholder so the request still logs.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        import time

        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        # Extract context from request
        target = request.query_params.get("target") or request.path_params.get("target")
        job_id = request.path_params.get("job_id") or request.path_params.get("id")

        # Skip logging health checks (too noisy)
        if request.url.path in ("/health", "/health/ready", "/"):
            return response

        # Auth context from DualAuthMiddleware — fall back to the legacy
        # "local" placeholder for endpoints that bypass auth (health,
        # docs, the auth lifecycle itself). ``getattr`` with a default
        # is essential: BaseHTTPMiddleware creates the request scope
        # before the upstream auth middleware writes state, so any
        # attribute access without a guard would raise AttributeError
        # and crash the audit path.
        user_id = getattr(request.state, "user_id", "local")
        username = getattr(request.state, "username", "local")
        jwt_jti = getattr(request.state, "jwt_jti", None)

        try:
            db = SessionLocal()
            try:
                audit = AuditLog(
                    action=f"{request.method}_{request.url.path}",
                    target=target,
                    job_id=job_id,
                    user_id=user_id,
                    username=username,
                    request_jwt_jti=jwt_jti,
                    details={
                        "method": request.method,
                        "path": str(request.url.path),
                        "status_code": response.status_code,
                        "duration_ms": round(duration * 1000, 2),
                    },
                )
                db.add(audit)
                db.commit()
            finally:
                db.close()
        except Exception:
            # Audit logging must never break the request
            pass

        return response
