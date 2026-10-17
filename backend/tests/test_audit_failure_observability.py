"""Regression test for 4R review R1-#3 (2026-10-16).

The AuditLogMiddleware used to swallow DB-write exceptions with a bare
`except Exception: pass`. If the audit_log table was missing,
the schema was bad, or the DB was down, the operator got NO signal
that 100% of audit rows were being lost.

The fix logs at ERROR with exc_info, but the request still succeeds
(audit failure is NOT a 5xx — the action is fulfilled; the operator's
SOC gets a real signal). This test exercises the failure path.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import structlog
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.audit.middleware import AuditLogMiddleware


@pytest.fixture
def failing_audit_app() -> FastAPI:
    """App whose AuditLogMiddleware cannot write to the audit_log table."""
    app = FastAPI()

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"status": "ok"}

    app.add_middleware(AuditLogMiddleware)
    return app


@pytest.mark.asyncio
async def test_audit_write_failure_does_not_break_request_but_logs_error(
    failing_audit_app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    """When the audit log DB write fails, the request still succeeds
    AND the operator sees a real ERROR log (R1-#3 fix)."""
    # Force SessionLocal() to raise on enter (covers the rare
    # `db = SessionLocal()` itself raising). Patch the import path the
    # middleware uses.
    import app.audit.middleware as audit_mod

    with patch.object(
        audit_mod, "SessionLocal", side_effect=RuntimeError("DB down")
    ):
        async with AsyncClient(
            transport=ASGITransport(app=failing_audit_app),
            base_url="http://test",
        ) as ac:
            # The request MUST still succeed — audit failure is not a 5xx.
            response = await ac.get("/ping")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}

    # The operator MUST see a real signal. The fix uses
    # structlog `logger.error`; pytest's caplog captures the log
    # record across all loggers.
    error_records = [r for r in caplog.records if r.levelname == "ERROR"]
    assert error_records, (
        "R1-#3 fix: audit write failure MUST log at ERROR; "
        "operator needs a real signal that the audit trail has a hole"
    )
    # The event name should identify the failure for downstream alerts.
    msg = " ".join(r.getMessage() for r in error_records)
    assert "audit_log_write_failed" in msg or "DB down" in str(
        [r.exc_info for r in error_records if r.exc_info]
    ), f"Expected audit_log_write_failed event or DB-down exc_info, got: {msg}"
