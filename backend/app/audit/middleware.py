"""Audit log middleware — logs all requests to AuditLog table."""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import SessionLocal
from app.models import AuditLog


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Log every API request to the AuditLog table.

    Captures: timestamp, action, target (from path/query), job_id (if present),
    user_id, details (method, path, status_code, duration).
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

        try:
            db = SessionLocal()
            try:
                audit = AuditLog(
                    action=f"{request.method}_{request.url.path}",
                    target=target,
                    job_id=job_id,
                    user_id="local",
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
        except Exception:  # noqa: BLE001
            # Audit logging must never break the request
            pass

        return response
