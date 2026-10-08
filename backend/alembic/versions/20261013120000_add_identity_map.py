"""add identity_map table

Revision ID: 20261013120000
Revises: 20261007224728
Create Date: 2026-10-13 12:00:00.000000

Adds the ``identity_map`` table that backs ``app.models.IdentityMap``
(PR 4 — person_dossier aggregator). The encrypted ``encrypted_email``
column holds a Fernet ciphertext keyed by the SHA-256 ``email_hash``;
the ``persona_id`` is the operator-facing pseudonym surfaced in DOSSIER
findings (e.g. ``Persona_001``).

The UNIQUE(job_id, email_hash) constraint enforces idempotency on
re-runs — a second insert for the same job+hash raises IntegrityError
which ``person_dossier._store_identity_map`` catches silently.

Reversibility is verified locally with
``alembic downgrade -1 && alembic upgrade head`` (per audit finding
R1-H2 / R4-M5: the lack of this migration left production deployments
running ``alembic upgrade head`` without the table, crashing mid-job
when ``_store_identity_map`` called ``db.flush()``).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "20261013120000"
down_revision: str | None = "20261007224728"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "identity_map",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(length=36),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email_hash", sa.String(length=64), nullable=False),
        sa.Column("encrypted_email", sa.Text(), nullable=False),
        sa.Column("persona_id", sa.String(length=20), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.UniqueConstraint("job_id", "email_hash", name="uq_identity_map_job_hash"),
    )
    op.create_index("ix_identity_map_job_id", "identity_map", ["job_id"])
    op.create_index("ix_identity_map_email_hash", "identity_map", ["email_hash"])


def downgrade() -> None:
    op.drop_index("ix_identity_map_email_hash", table_name="identity_map")
    op.drop_index("ix_identity_map_job_id", table_name="identity_map")
    op.drop_table("identity_map")
