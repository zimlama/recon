"""Tests for ``app.auth.usage.query_legacy_usage`` (PR-J3.7).

Spec coverage (engram #1431, REQ-LEG-003 / 004 / 006 / 009 / 010):

- Empty DB → ``total_legacy_requests==0``, ``unique_ips==0``, ``rows==[]``
- Non-legacy rows (``username='jwt'``) excluded
- ``details.ip == 'unknown'`` rows aggregate under the literal key
  ``"unknown"`` (REQ-LEG-009) so operators detect test-harness /
  upstream-proxy noise
- Top-5 truncation: 8 distinct paths used by IP ``1.2.3.4`` →
  ``sample_paths`` length is 5 (REQ-LEG-010)
- ``?since`` window filter: rows before ``since`` excluded
- Per-IP user-agent subqueries: ``first_user_agent`` /
  ``last_user_agent`` populate correctly

The service returns ``list[dict]`` (NOT Pydantic) — schema validation
lives at the FastAPI boundary (per design D2).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.auth.usage import query_legacy_usage
from app.database import Base, SessionLocal, engine
from app.models import AuditLog


def _seed(
    db,
    *,
    username: str = "legacy",
    ip: str = "1.2.3.4",
    path: str = "/api/v1/jobs",
    user_agent: str | None = None,
    when: datetime | None = None,
    status: int = 200,
) -> None:
    when = when or datetime(2026, 10, 1, tzinfo=UTC)
    details: dict = {
        "method": "GET",
        "path": path,
        "status_code": status,
        "duration_ms": 1.0,
        "ip": ip,
        "auth_method": "legacy",
    }
    if user_agent is not None:
        details["user_agent"] = user_agent
    db.add(
        AuditLog(
            timestamp=when,
            action=f"GET_{path}",
            target=None,
            job_id=None,
            user_id="local",
            username=username,
            request_jwt_jti=None,
            details=details,
        )
    )
    db.commit()


@pytest.fixture
def db_session():
    """Yield a fresh session with empty audit_log per test."""
    Base.metadata.create_all(bind=engine)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.query(AuditLog).delete()
        db.commit()
        yield db
    finally:
        db.query(AuditLog).delete()
        db.commit()
        db.close()


def test_empty_db_returns_empty_aggregation(db_session) -> None:
    """Empty DB → zero totals, no rows.

    Mirrors the post-deploy zero-history case so operators don't
    see an unrelated 5xx.
    """
    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    rows, totals = query_legacy_usage(db_session, since=now - timedelta(days=30))
    assert totals["total_legacy_requests"] == 0
    assert totals["unique_ips"] == 0
    assert rows == []


def test_excludes_non_legacy_rows(db_session) -> None:
    """``username='jwt'`` rows excluded — only legacy counts."""

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    # 1 legacy row (counts), 2 jwt rows (excluded).
    _seed(db_session, username="legacy", ip="1.2.3.4")
    _seed(db_session, username="jwt", ip="5.6.7.8")
    _seed(db_session, username="jwt", ip="9.10.11.12")

    rows, totals = query_legacy_usage(db_session, since=now - timedelta(days=30))
    assert totals["total_legacy_requests"] == 1
    assert totals["unique_ips"] == 1
    assert [r["ip"] for r in rows] == ["1.2.3.4"]


def test_unknown_ip_bucket_aggregates(db_session) -> None:
    """``details.ip=='unknown'`` (no client) → one row with key ``unknown``."""

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    _seed(db_session, ip="unknown")
    _seed(db_session, ip="unknown")
    _seed(db_session, ip="unknown", path="/api/v1/modules")
    _seed(db_session, ip="1.2.3.4")

    rows, totals = query_legacy_usage(db_session, since=now - timedelta(days=30))
    assert totals["total_legacy_requests"] == 4
    assert totals["unique_ips"] == 2
    ips = sorted(r["ip"] for r in rows)
    assert ips == ["1.2.3.4", "unknown"]
    unknown_row = next(r for r in rows if r["ip"] == "unknown")
    assert unknown_row["request_count"] == 3


def test_top_5_sample_paths_truncation(db_session) -> None:
    """8 distinct paths from one IP → ``sample_paths`` length is 5."""

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    # 8 distinct paths; ``/api/v1/jobs`` x 3 so it ranks first.
    base = datetime(2026, 10, 1, tzinfo=UTC)
    paths_used = [
        "/api/v1/jobs",
        "/api/v1/jobs",
        "/api/v1/jobs",
        "/api/v1/modules",
        "/api/v1/modules",
        "/api/v1/findings",
        "/api/v1/reports",
        "/api/v1/handoff",
        "/api/v1/ai",
    ]
    for i, p in enumerate(paths_used):
        _seed(
            db_session,
            ip="1.2.3.4",
            path=p,
            when=base + timedelta(seconds=i),
        )

    rows, _ = query_legacy_usage(db_session, since=now - timedelta(days=30))
    assert len(rows) == 1
    sample_paths = rows[0]["sample_paths"]
    assert len(sample_paths) == 5
    # Top entry must be the most-frequent path.
    assert sample_paths[0] == "/api/v1/jobs"


def test_since_window_filter(db_session) -> None:
    """Rows with ``timestamp < since`` are excluded."""

    since = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    # Inside window (after since)
    _seed(
        db_session,
        ip="1.2.3.4",
        when=since + timedelta(hours=1),
    )
    # Outside window (before since, well past 365 d cap)
    _seed(
        db_session,
        ip="5.6.7.8",
        when=since - timedelta(days=400),
    )

    rows, totals = query_legacy_usage(db_session, since=since)
    assert totals["total_legacy_requests"] == 1
    assert [r["ip"] for r in rows] == ["1.2.3.4"]


def test_user_agent_subqueries_populate(db_session) -> None:
    """``first_user_agent`` / ``last_user_agent`` populate via correlated
    subqueries (or window functions — implementation choice) so that
    operators see WHO made the legacy calls.
    """

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    base = datetime(2026, 10, 1, tzinfo=UTC)
    _seed(db_session, ip="1.2.3.4", user_agent="ua-first", when=base)
    _seed(
        db_session,
        ip="1.2.3.4",
        user_agent="ua-last",
        when=base + timedelta(days=10),
    )
    _seed(
        db_session,
        ip="1.2.3.4",
        user_agent="ua-middle",
        when=base + timedelta(days=5),
    )

    rows, _ = query_legacy_usage(db_session, since=now - timedelta(days=30))
    assert len(rows) == 1
    row = rows[0]
    assert row["first_user_agent"] == "ua-first"
    assert row["last_user_agent"] == "ua-last"


def test_rows_ordered_request_count_desc(db_session) -> None:
    """Rows ordered ``request_count DESC`` (REQ-LEG-003 primary key).

    The implementation may also secondary-sort on
    ``last_used_at DESC``; that ordering constraint is NOT pinned
    here so the test doesn't over-couple to an implementation detail."""

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    # 1 request from one IP, 3 from another.
    for _ in range(3):
        _seed(db_session, ip="1.2.3.4")
    _seed(db_session, ip="5.6.7.8")

    rows, _ = query_legacy_usage(db_session, since=now - timedelta(days=30))
    counts = [r["request_count"] for r in rows]
    assert counts == sorted(counts, reverse=True)
    assert counts[0] == 3


def test_returns_dicts_not_pydantic(db_session) -> None:
    """Service layer returns plain dicts (design D2 — dialect-agnostic)."""

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
    _seed(db_session, ip="1.2.3.4")
    rows, totals = query_legacy_usage(db_session, since=now - timedelta(days=30))
    assert isinstance(rows, list)
    assert isinstance(rows[0], dict)
    assert isinstance(totals, dict)
