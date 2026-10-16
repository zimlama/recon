# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Observability (REQ-INB-011).

Spec REQ-INB-011 mandates that on every 429:

1. One structlog WARNING with ``event="rate_limit_exceeded"`` and the
   documented fields (``scope``, ``key``, ``endpoint``, ``retry_after_seconds``,
   ``request_id``, ``user_id``).
2. One ``audit_log`` row with ``action="rate_limit"`` and the
   ``details`` payload.

Emission MUST be synchronous — no async gap. We capture structlog via
its in-process ``capture_logs`` context manager; the audit row lands
in the same SQLite session as the response.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
import structlog
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.database import Base, SessionLocal, engine
from app.models import AuditLog
from app.ratelimit import RateLimitMiddleware, compile_rate_limit_patterns


@pytest.fixture
def app_with_logger() -> Iterator[FastAPI]:
    """Tiny app + a fresh in-process DB so the audit row count is clean."""
    app = FastAPI()
    patterns = compile_rate_limit_patterns({"/api/v1/auth/login": (1, 60)})
    app.state.rate_limit_patterns = patterns

    @app.post("/api/v1/auth/login")
    async def _login(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    app.add_middleware(RateLimitMiddleware)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield app
    Base.metadata.drop_all(bind=engine)


@pytest.mark.asyncio
async def test_structlog_warning_and_audit_row_emitted(app_with_logger: FastAPI) -> None:
    """Both signals land in the same request lifecycle (REQ-INB-011)."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_logger), base_url="http://test"
    ) as ac:
        # First 200 — no observability fires.
        r = await ac.post("/api/v1/auth/login")
        assert r.status_code == 200
        # Second rejects — 1 structlog + 1 audit_log row.
        with structlog.testing.capture_logs() as captured:
            r = await ac.post("/api/v1/auth/login")
        assert r.status_code == 429

        rate_limit_events = [
            e for e in captured if e.get("event") == "rate_limit_exceeded"
        ]
        assert len(rate_limit_events) == 1, (
            f"Expected 1 rate_limit_exceeded event, got {len(rate_limit_events)}"
        )
        evt = rate_limit_events[0]
        for field in ("scope", "key", "endpoint", "retry_after_seconds"):
            assert field in evt, f"Missing {field!r} in {evt!r}"

        # Audit row.
        with SessionLocal() as db:
            rows = db.query(AuditLog).filter(AuditLog.action == "rate_limit").all()
        assert len(rows) == 1, (
            f"Expected 1 audit_log row, got {len(rows)}"
        )
        row = rows[0]
        assert row.details["scope"] == "ip"
        assert row.details["endpoint"] == r"^/api/v1/auth/login$"
        assert "retry_after_seconds" in row.details


@pytest.mark.asyncio
async def test_no_audit_or_structlog_on_allow(app_with_logger: FastAPI) -> None:
    """Successful requests MUST NOT emit 429-only observability (R-3 sanity)."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_logger), base_url="http://test"
    ) as ac:
        with structlog.testing.capture_logs() as captured:
            r = await ac.post("/api/v1/auth/login")
        assert r.status_code == 200

        rl_events = [
            e for e in captured if e.get("event") == "rate_limit_exceeded"
        ]
        assert rl_events == [], (
            f"Successful request must NOT emit rate_limit_exceeded; got {rl_events!r}"
        )

        with SessionLocal() as db:
            rows = db.query(AuditLog).filter(AuditLog.action == "rate_limit").all()
        assert rows == [], "Successful request must NOT write a rate_limit row"


__all__: list[str] = []
