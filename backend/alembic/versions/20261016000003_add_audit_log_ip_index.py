"""add functional index on audit_log(details->'$.ip') for legacy usage stats

Revision ID: 20261016000003
Revises: 20261014000002
Create Date: 2026-10-16 17:00:00.000000

PR-J3.7 (legacy RECON_API_KEY usage-stats, sec-auth-jwt Issue #29).

Adds a partial JSON-expression index that keeps the
``GET /api/v1/auth/legacy-usage-stats`` aggregation
(``app.auth.usage.query_legacy_usage``) sub-millisecond past 1M
legacy rows. Without this index, the GROUP BY on
``json_extract(details, '$.ip')`` would full-scan ``audit_log``
every time an admin runs the dashboard, which would degrade the
endpoint's p99 latency as the deprecation window progresses.

Index shape
-----------
::

    CREATE INDEX IF NOT EXISTS ix_audit_log_legacy_ip_ts
      ON audit_log (username, json_extract(details, '$.ip'), timestamp)
      WHERE username = 'legacy';

The ``WHERE username = 'legacy'`` predicate makes the index
partial — JWT-authenticated and dev-bypass rows never appear in
the legacy-usage aggregation, so they're excluded from the
index. This keeps the index size proportional to legacy-key
consumers (~10K rows over the deprecation window) instead of
the entire ``audit_log`` table.

Compatibility (NFR-LEG-005)
---------------------------
- **SQLite** (project default per ``2026-10-06``): ``json_extract``
  is available natively. ``CREATE INDEX IF NOT EXISTS`` is
  supported since SQLite 3.8.
- **Postgres**: ``json_extract`` is available via the JSON /
  JSONB operator family — identical syntax. MySQL would need a
  virtual generated column instead (excluded per spec).
- **MySQL**: NOT supported. Tracked for future port.

Reversible: ``alembic downgrade -1`` drops the index. The
``audit_log`` table itself and the pre-existing data are
untouched.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "20261016000003"
down_revision: str | None = "20261014000002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# The index name is fixed so test_migration_audit_log_ip_index can
# assert on ``PRAGMA index_list('audit_log')`` and so the
# ``downgrade`` step can drop it deterministically.
_INDEX_NAME = "ix_audit_log_legacy_ip_ts"


def upgrade() -> None:
    """Create the partial JSON-expression index on ``audit_log``.

    SQLite + Postgres ONLY (NFR-LEG-005). The
    ``backend/app/auth/usage.py`` aggregator benefits from this
    index; the cross-cutting ``AuditLogMiddleware`` extension
    (``backend/app/audit/middleware.py``) is the additive detail
    change that makes the GROUP BY key meaningful.
    """
    op.execute(
        f"CREATE INDEX IF NOT EXISTS {_INDEX_NAME} "
        "ON audit_log "
        "(username, json_extract(details, '$.ip'), timestamp) "
        "WHERE username = 'legacy'"
    )


def downgrade() -> None:
    """Drop the partial JSON-expression index.

    Reversible cleanly: ``audit_log`` rows are untouched. Useful
    when an operator wants to reclaim the index space during a
    rollback-then-redeploy cycle.
    """
    op.execute(f"DROP INDEX IF EXISTS {_INDEX_NAME}")
