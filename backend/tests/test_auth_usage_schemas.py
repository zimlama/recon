"""Tests for ``LegacyUsageStatsResponse`` + ``LegacyUsageStatsRow`` (PR-J3.7).

Spec coverage (engram #1431, REQ-LEG-005):

- ``LegacyUsageStatsResponse`` is Pydantic v2 with ``extra="forbid"``.
- ``sample_paths`` enforces ``max_length=5`` (REQ-LEG-010).
- ISO 8601 round-trip for every datetime field (``since`` /
  ``as_of`` / ``first_used_at`` / ``last_used_at``).
- Row ordering pins ``request_count DESC`` (REQ-LEG-003) — the schema
  doesn't enforce order but the router does.

These tests target the Pydantic v2 surface area only; the
service-layer SQL aggregator is exercised in ``test_auth_usage_query``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.auth.schemas import LegacyUsageStatsResponse, LegacyUsageStatsRow


def _ts(year: int, month: int, day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def _row(
    *,
    ip: str = "1.2.3.4",
    request_count: int = 5,
    first_used_at: datetime | None = _ts(2026, 9, 1),
    last_used_at: datetime | None = _ts(2026, 9, 20),
    first_user_agent: str = "ua-1",
    last_user_agent: str = "ua-2",
    sample_paths: list[str] | None = None,
) -> dict:
    return {
        "ip": ip,
        "request_count": request_count,
        "first_used_at": first_used_at,
        "last_used_at": last_used_at,
        "first_user_agent": first_user_agent,
        "last_user_agent": last_user_agent,
        "sample_paths": sample_paths or ["/api/v1/jobs"],
    }


def _response(
    *,
    since: datetime = _ts(2026, 9, 16),
    as_of: datetime = _ts(2026, 10, 16),
    window_days: int = 30,
    total_legacy_requests: int = 5,
    unique_ips: int = 1,
    rows: list[dict] | None = None,
) -> dict:
    if rows is None:
        rows = [_row()]
    return {
        "since": since,
        "as_of": as_of,
        "window_days": window_days,
        "total_legacy_requests": total_legacy_requests,
        "unique_ips": unique_ips,
        "rows": rows,
    }


def test_legacy_usage_stats_response_accepts_canonical_body() -> None:
    """Happy-path body matches the spec example."""

    body = _response()
    response = LegacyUsageStatsResponse.model_validate(body)
    assert response.window_days == 30
    assert response.total_legacy_requests == 5
    assert response.unique_ips == 1
    assert len(response.rows) == 1
    row = response.rows[0]
    assert row.ip == "1.2.3.4"
    assert row.sample_paths == ["/api/v1/jobs"]


def test_legacy_usage_stats_response_rejects_unknown_keys() -> None:
    """``extra='forbid'`` — unknown top-level keys raise ValidationError."""

    body = _response()
    body["unexpected_top"] = "no"
    with pytest.raises(ValidationError):
        LegacyUsageStatsResponse.model_validate(body)


def test_legacy_usage_stats_row_rejects_unknown_keys() -> None:
    """``extra='forbid'`` is also enforced on the inner Row model."""

    row = _row()
    row["extra_field"] = "nope"
    with pytest.raises(ValidationError):
        LegacyUsageStatsRow.model_validate(row)


def test_sample_paths_max_length_5() -> None:
    """``sample_paths`` is bounded to 5 entries (REQ-LEG-010)."""

    row = _row(sample_paths=["/a", "/b", "/c", "/d", "/e"])
    assert LegacyUsageStatsRow.model_validate(row).sample_paths == [
        "/a",
        "/b",
        "/c",
        "/d",
        "/e",
    ]

    row_over = _row(sample_paths=["/a", "/b", "/c", "/d", "/e", "/f"])
    with pytest.raises(ValidationError):
        LegacyUsageStatsRow.model_validate(row_over)


def test_iso8601_round_trip_on_all_datetime_fields() -> None:
    """Every datetime field round-trips a Python tz-aware ``datetime``.

    The endpoint's contract is ISO 8601-with-Z; Pydantic must accept
    both naive UTC and offset-aware strings. Pydantic v2 normalises
    naive datetimes to UTC by default — pinned here so the schema
    doesn't quietly regress."""

    body = _response(
        since=_ts(2026, 9, 16, 12, 30),
        as_of=_ts(2026, 10, 16, 8, 0),
    )
    body["rows"][0]["first_used_at"] = _ts(2026, 9, 1, 9, 15)
    body["rows"][0]["last_used_at"] = _ts(2026, 9, 20, 18, 45)
    response = LegacyUsageStatsResponse.model_validate(body)
    # Round-trip via model_dump(mode="json") — the endpoint ships JSON.
    dumped = response.model_dump(mode="json")
    rebuilt = LegacyUsageStatsResponse.model_validate(dumped)
    assert rebuilt == response


def test_response_with_empty_rows() -> None:
    """Empty list — REQ-LEG-003 says empty audit_log → 200 + zero totals."""

    body = _response(
        total_legacy_requests=0,
        unique_ips=0,
        rows=[],
    )
    response = LegacyUsageStatsResponse.model_validate(body)
    assert response.total_legacy_requests == 0
    assert response.unique_ips == 0
    assert response.rows == []
