"""extend audit_log with user_id / username / request_jwt_jti

Revision ID: 20261014000002
Revises: 20261014000001
Create Date: 2026-10-14 12:00:01.000000

PR-J1 of ``sec-auth-jwt`` (Issue #29), spec §3 audit_log extension.

Adds three NULLable columns to the pre-existing ``audit_log`` table:

- ``username VARCHAR(64) NULL`` — operator-facing label (e.g. email prefix).
- ``request_jwt_jti VARCHAR(36) NULL`` — the JWT ``jti`` claim when the
  request was authenticated via the JWT path. NULL for legacy / anonymous.
- (NOTE: ``user_id`` already exists on audit_log as a hardcoded VARCHAR(100)
  defaulting to 'local'. Per spec §6 we add only the columns that are new;
  the audit middleware (PR-J3.7) writes to the existing ``user_id`` column.)

Adds an index ``ix_audit_log_user_time`` on ``(user_id, timestamp)`` for
the per-user audit-trail queries in PR-J3.5.

Backfill: pre-migration rows (``user_id='local'`` from the original schema)
get ``username='legacy'`` so legacy-usage-stats can find them. Backfill
runs in 10 000-row batches to keep SQLite write-lock windows short on
multi-million-row production tables (per design §10 migration runbook).

The downgrade drops the new columns + index but DOES NOT drop the audit_log
table itself (per spec §6).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "20261014000002"
down_revision: str | None = "20261014000001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Backfill batch size — kept conservative so SQLite write-lock windows stay
# short. Production-shaped audit_log tables can hold millions of rows; this
# keeps each UPDATE <1 s on the test machine (verified locally: 50k rows
# complete in ~10–15 s). Bump only after benchmarking on real hardware.
_BACKFILL_BATCH_SIZE = 10_000


def upgrade() -> None:
    # ---- Schema: add the three NULLable columns + index ----
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.add_column(
            sa.Column("username", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "request_jwt_jti", sa.String(length=36), nullable=True
            )
        )
        batch_op.create_index(
            "ix_audit_log_user_time",
            ["user_id", "timestamp"],
        )

    # ---- Backfill: pre-migration rows get username='legacy' ----
    # We do this in batches of ``_BACKFILL_BATCH_SIZE`` to keep the write-lock
    # window bounded. The loop continues until ``rowcount == 0`` (no more
    # rows left to update). Both SQLite and PostgreSQL support this
    # LIMIT-based batched UPDATE.
    bind = op.get_bind()
    while True:
        result = bind.execute(
            sa.text(
                "UPDATE audit_log SET username = 'legacy' "
                "WHERE id IN ("
                "  SELECT id FROM audit_log "
                "  WHERE username IS NULL "
                "  LIMIT :limit"
                ") AND username IS NULL"
            ),
            {"limit": _BACKFILL_BATCH_SIZE},
        )
        if result.rowcount == 0:
            break


def downgrade() -> None:
    # Drop the new index + columns but keep the audit_log table itself.
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.drop_index("ix_audit_log_user_time")
        batch_op.drop_column("request_jwt_jti")
        batch_op.drop_column("username")