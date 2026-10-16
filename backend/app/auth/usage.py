"""Operator-facing legacy-key usage stats (PR-J3.7, sec-auth-jwt).

The ``RECON_API_KEY`` static Bearer token is being phased out at
``v0.3.0`` (PR-J8 in the parent sec-auth-jwt track). To make the
2-release deprecation window defensible, operators need an
admin-only dashboard that enumerates the IPs still using the
legacy key — so they can reach out before the flip. This module
is the read-only aggregation: ``query_legacy_usage(db, since)``.

Schema reads (PR-J3.7 contract, REQ-013 mod):

- ``audit_log.username == 'legacy'`` is the canonical filter —
  ``DualAuthMiddleware`` (``backend/app/auth/middleware.py:269-287``)
  writes that marker when the Bearer matches the legacy static
  API key.
- ``audit_log.details`` is a JSON column; ``json_extract`` reads
  ``details.ip`` (added by ``AuditLogMiddleware`` in PR-J3.7) and
  ``details.path`` / ``details.user_agent``. SQLite and Postgres
  both support identical ``json_extract(col, '$.key')`` syntax;
  MySQL is excluded (project is SQLite-only per ``2026-10-06``).

Output shape (PR-J3.7 design D-J3.7.2):

``(rows, totals)`` where ``rows`` is a ``list[dict]`` (NOT
Pydantic — schema validation lives at the FastAPI boundary per
design D2) and ``totals`` is ``{total_legacy_requests,
unique_ips}``. ``sample_paths`` is the top-5 distinct
``details.path`` per IP, ordered by per-IP frequency DESC
(REQ-LEG-010).

Performance budget: with the new partial index
``ix_audit_log_legacy_ip_ts`` on ``(username,
json_extract(details, '$.ip'), timestamp)`` (PR-J3.7 migration
20261016000003) the GROUP BY stays sub-millisecond past 1M legacy
rows (spec NFR-LEG-005).

Reference
---------
- engram #1431 (proposal): option-A aggregation; design D-J3.7.1
- engram #1431 (design): data flow + risk #2 (DoS via unbounded
  scan → 365 d hard cap lives at the router layer, not here;
  this module is unbounded by design)
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

# SQL aggregator (#1): IP rollup. Two correlated subqueries resolve
# first / last user-agent per IP via ``json_extract``. The
# ``json_extract`` form works identically on SQLite and Postgres
# (project is SQLite-only; the JSON path is well-tested in both
# engines). We MUST read user_agent from json_extract because the
# raw ``details`` JSON column is stored as TEXT under SQLite and
# would need an extra ``json.loads`` round-trip.
_IP_ROLLUP_SQL = text(
    """
    SELECT
        json_extract(details, '$.ip') AS ip,
        COUNT(*) AS request_count,
        MIN(timestamp) AS first_used_at,
        MAX(timestamp) AS last_used_at,
        (
            SELECT json_extract(a2.details, '$.user_agent')
            FROM audit_log AS a2
            WHERE a2.username = 'legacy'
              AND json_extract(a2.details, '$.ip') = json_extract(a1.details, '$.ip')
            ORDER BY a2.timestamp ASC
            LIMIT 1
        ) AS first_user_agent,
        (
            SELECT json_extract(a3.details, '$.user_agent')
            FROM audit_log AS a3
            WHERE a3.username = 'legacy'
              AND json_extract(a3.details, '$.ip') = json_extract(a1.details, '$.ip')
            ORDER BY a3.timestamp DESC
            LIMIT 1
        ) AS last_user_agent
    FROM audit_log AS a1
    WHERE username = 'legacy'
      AND timestamp >= :since
    GROUP BY json_extract(details, '$.ip')
    ORDER BY request_count DESC, last_used_at DESC
    """
)


# SQL sub-aggregator (#2): per-IP path frequency.
_PATH_FREQ_SQL = text(
    """
    SELECT
        json_extract(details, '$.ip') AS ip,
        json_extract(details, '$.path') AS path
    FROM audit_log
    WHERE username = 'legacy'
      AND timestamp >= :since
    """
)


def _user_agent_or_unknown(value: object) -> str:
    """Coerce a ``json_extract`` result into a usable user-agent string."""

    if isinstance(value, str) and value:
        return value
    return "unknown"


def _paths_per_ip(rows_for_ip: Iterable[str | None]) -> list[str]:
    """Return the top-5 distinct ``path`` values ordered by per-IP
    frequency DESC (REQ-LEG-010)."""

    counts: dict[str, int] = {}
    for p in rows_for_ip:
        if not isinstance(p, str) or not p:
            continue
        counts[p] = counts.get(p, 0) + 1
    for p in rows_for_ip:
        if not isinstance(p, str) or not p:
            continue
        counts[p] = counts.get(p, 0) + 1

    ranked = sorted(
        counts.items(), key=lambda kv: (-kv[1], kv[0])
    )
    return [path for path, _ in ranked[:5]]


def query_legacy_usage(
    db: Session,
    *,
    since: datetime,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Aggregate legacy-key usage from ``audit_log``.

    Two round-trips:

    1. Per-IP rollup — ``COUNT(*)``, ``MIN/MAX(timestamp)``,
       first / last user-agent via correlated subqueries.
    2. Per-IP top-5 paths — single scan, then in-Python group +
       sort + slice to avoid a third round-trip.

    Returns ``(rows, totals)`` where ``rows`` is a list of dicts
    keyed by the spec response shape (``ip``,
    ``request_count``, ``first_used_at``, ``last_used_at``,
    ``first_user_agent``, ``last_user_agent``,
    ``sample_paths``).
    """
    # ---- 1. Per-IP rollup ----
    ip_rows = db.execute(_IP_ROLLUP_SQL, {"since": since}).mappings().all()

    # ---- 2. Per-IP path frequency (single scan, grouped in Python) ----
    # The (ip, path) tuples are grouped into a dict-of-lists keyed on
    # the IP so _paths_per_ip can rank-and-slice without a third
    # round-trip.
    path_raw = db.execute(_PATH_FREQ_SQL, {"since": since}).all()

    paths_by_ip: dict[str, list[str | None]] = {}
    for ip_value, path_value in path_raw:
        key = str(ip_value) if ip_value is not None else "unknown"
        if not key:
            key = "unknown"
        paths_by_ip.setdefault(key, []).append(
            str(path_value) if path_value is not None else None
        )

    rows: list[dict[str, Any]] = []
    total_legacy_requests = 0
    for mapping in ip_rows:
        ip_value = mapping["ip"]
        ip_key = str(ip_value) if ip_value is not None else "unknown"
        if not ip_key:
            ip_key = "unknown"

        request_count = int(mapping["request_count"] or 0)
        total_legacy_requests += request_count

        rows.append(
            {
                "ip": ip_key,
                "request_count": request_count,
                "first_used_at": mapping["first_used_at"],
                "last_used_at": mapping["last_used_at"],
                "first_user_agent": _user_agent_or_unknown(
                    mapping["first_user_agent"]
                ),
                "last_user_agent": _user_agent_or_unknown(
                    mapping["last_user_agent"]
                ),
                "sample_paths": _paths_per_ip(
                    paths_by_ip.get(ip_key, [])
                ),
            }
        )

    totals = {
        "total_legacy_requests": total_legacy_requests,
        "unique_ips": len(rows),
    }
    return rows, totals


__all__ = ["query_legacy_usage"]
