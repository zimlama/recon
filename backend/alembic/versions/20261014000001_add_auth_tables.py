"""add auth_users and refresh_tokens tables

Revision ID: 20261014000001
Revises: 20261013120000
Create Date: 2026-10-14 12:00:00.000000

Adds the two tables that back PR-J1 of ``sec-auth-jwt`` (Issue #29):

- ``auth_users`` — per-user credentials, role, scopes, lockout state.
- ``refresh_tokens`` — opaque DB-backed refresh tokens with HMAC-SHA256
  hashes, family revocation, and rotation-on-use.

Both are new tables — no migration of legacy state is required because they
start empty. The columns mirror the spec at engram #1371 §3.

Reversibility is verified locally with
``alembic downgrade -1 && alembic upgrade head`` (per audit finding
R1-H2 / R4-M5: missing migrations caused mid-job crashes in earlier
releases).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "20261014000001"
down_revision: str | None = "20261013120000"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "auth_users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.Column(
            "failed_login_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("email", name="uq_auth_users_email"),
        sa.CheckConstraint(
            "role IN ('admin', 'operator', 'service')",
            name="ck_auth_users_role",
        ),
    )
    op.create_index("ix_auth_users_role", "auth_users", ["role"])
    op.create_index("ix_auth_users_disabled_at", "auth_users", ["disabled_at"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("auth_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.String(length=36), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column(
            "replaced_by",
            sa.String(length=36),
            sa.ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("ip_first_seen", sa.String(length=64), nullable=True),
        sa.Column("user_agent_first_seen", sa.String(length=512), nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
    )
    op.create_index(
        "ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"]
    )
    op.create_index(
        "ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"]
    )
    op.create_index(
        "ix_refresh_tokens_revoked_at", "refresh_tokens", ["revoked_at"]
    )
    op.create_index(
        "ix_refresh_tokens_user_expires",
        "refresh_tokens",
        ["user_id", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_user_expires", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_revoked_at", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    op.drop_index("ix_auth_users_disabled_at", table_name="auth_users")
    op.drop_index("ix_auth_users_role", table_name="auth_users")
    op.drop_table("auth_users")