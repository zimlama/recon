"""add roe and sign_off tables

Revision ID: 20261007224728
Revises:
Create Date: 2026-10-07 22:47:28.000000

Adds the two tables that back `app.models.RoE` and `app.models.SignOff`:
- `roes` (one row per engagement envelope)
- `sign_offs` (human authorization records attached to an RoE)

`sign_offs.roe_id` carries `ON DELETE CASCADE` so removing an RoE in the
DB automatically removes its signoffs. The ORM also enforces the same
cascade at the Python level (`cascade="all, delete-orphan"` on the
`RoE.sign_offs` relationship) — both are needed because SQLite ignores
the FK pragma unless the connection has `PRAGMA foreign_keys=ON`.

Reversibility is verified locally with
`alembic downgrade -1 && alembic upgrade head`.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "20261007224728"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "roes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("scope_type", sa.String(length=50), nullable=False),
        sa.Column("scope_value", sa.String(length=255), nullable=False),
        sa.Column("authorized_by", sa.String(length=100), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=False,
            server_default="draft",
        ),
        sa.Column("valid_from", sa.DateTime(), nullable=False),
        sa.Column("valid_until", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_roes_target", "roes", ["target"])
    op.create_index("ix_roes_status", "roes", ["status"])

    op.create_table(
        "sign_offs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "roe_id",
            sa.String(length=36),
            sa.ForeignKey("roes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("signer_name", sa.String(length=100), nullable=False),
        sa.Column("signer_email", sa.String(length=255), nullable=False),
        sa.Column("signer_role", sa.String(length=100), nullable=False),
        sa.Column("signed_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_sign_offs_roe_id", "sign_offs", ["roe_id"])


def downgrade() -> None:
    op.drop_index("ix_sign_offs_roe_id", table_name="sign_offs")
    op.drop_table("sign_offs")
    op.drop_index("ix_roes_status", table_name="roes")
    op.drop_index("ix_roes_target", table_name="roes")
    op.drop_table("roes")