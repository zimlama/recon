"""Tests for the PR-J1 auth alembic revisions.

Covers two revisions:

1. ``20261014000001_add_auth_tables``: creates ``auth_users`` + ``refresh_tokens``
   with the spec'd columns, indexes, and constraints. Round-trip
   (upgrade + downgrade + upgrade) must be lossless for the pre-existing
   ``audit_log`` table — only the new tables come and go.

2. ``20261014000002_extend_audit_log_with_user``: adds three NULLable columns
   (``user_id``, ``username``, ``request_jwt_jti``) + an index, then backfills
   pre-migration rows with ``username='legacy'``. Backfill MUST be split into
   10 000-row batches and MUST complete against a 50 000-row audit_log in
   <30 s on the test machine.

We run these against a real Alembic env using a per-test SQLite file in
``tmp_path``. The existing ``alembic/env.py`` reads DATABASE_URL from
``app.config.get_settings()``, which is cached via ``lru_cache`` — so we
clear that cache and set the env var per test.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, event, text

from alembic import command as alembic_command


def _make_sqlite_engine(db_url: str):
    """Build a SQLite engine with FK enforcement + WAL + busy_timeout.

    Mirrors ``app.database._set_sqlite_pragma`` so cascade deletes are
    actually enforced (SQLite ignores FK constraints unless the connection
    has ``PRAGMA foreign_keys=ON``).
    """
    engine = create_engine(db_url)

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _conn_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    return engine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alembic_config(db_url: str) -> AlembicConfig:
    """Build an Alembic config that points at the given DB URL."""
    backend = Path(__file__).resolve().parents[1]
    cfg = AlembicConfig(str(backend / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def _seed_pre_migration_schema(db_url: str) -> None:
    """Create the pre-PR-J1 schema (audit_log only) directly via raw SQL.

    We do NOT go through ``Base.metadata.create_all`` because that would also
    create the new auth tables via ORM — bypassing the migration we're
    testing. Instead we run hand-written SQL that mirrors what Alembic rev
    ``20261013120000_add_identity_map`` would leave behind.
    """
    engine = _make_sqlite_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    target VARCHAR(255),
                    job_id VARCHAR(36),
                    user_id VARCHAR(100) NOT NULL DEFAULT 'local',
                    details JSON NOT NULL DEFAULT '{}'
                )
                """
            )
        )
        conn.execute(text("CREATE INDEX ix_audit_log_timestamp ON audit_log (timestamp)"))
        conn.execute(text("CREATE INDEX ix_audit_log_action ON audit_log (action)"))
        conn.execute(text("CREATE INDEX ix_audit_log_target ON audit_log (target)"))
        conn.execute(text("CREATE INDEX ix_audit_log_job_id ON audit_log (job_id)"))
        conn.execute(text("CREATE INDEX ix_audit_log_user_id ON audit_log (user_id)"))
    engine.dispose()


def _seed_audit_rows(db_url: str, n: int) -> None:
    """Insert n audit_log rows directly via SQL — fast bulk insert for the
    backfill timing test. Each row has user_id='local' (the pre-migration
    default) and a unique timestamp.
    """
    engine = _make_sqlite_engine(db_url)
    with engine.begin() as conn:
        for i in range(n):
            conn.execute(
                text(
                    "INSERT INTO audit_log (timestamp, action, target, user_id, details) "
                    "VALUES (:ts, :action, :target, 'local', '{}')"
                ),
                {
                    "ts": f"2026-01-{(i % 28) + 1:02d} 12:00:00.{i % 1000:03d}",
                    "action": "TEST_BULK",
                    "target": f"target-{i}",
                },
            )
    engine.dispose()


@pytest.fixture
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Per-test SQLite file. Pre-seeds the audit_log schema so revisions
    that depend on it can apply cleanly.

    Returns the DB URL (sqlite:///<path>).
    """
    db_file = tmp_path / "recon.db"
    db_url = f"sqlite:///{db_file}"

    # Reset Settings cache so the per-test DATABASE_URL is picked up by
    # anything that calls get_settings() (alembic env, etc.).
    monkeypatch.setenv("DATABASE_URL", db_url)
    from app.config import get_settings

    get_settings.cache_clear()

    # Seed the baseline schema (the state right after rev 20261013120000).
    _seed_pre_migration_schema(db_url)

    yield db_url

    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Revision 1 — auth_users + refresh_tokens
# ---------------------------------------------------------------------------


def test_revision_1_creates_auth_users_table(isolated_db: str) -> None:
    """After upgrade head, auth_users exists with the spec'd columns."""
    cfg = _make_alembic_config(isolated_db)
    alembic_command.upgrade(cfg, "head")

    engine = _make_sqlite_engine(isolated_db)
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA table_info(auth_users)")).fetchall()
        cols = {row[1] for row in rows}

    assert "id" in cols, "auth_users.id missing"
    assert "email" in cols, "auth_users.email missing"
    assert "password_hash" in cols, "auth_users.password_hash missing"
    assert "role" in cols, "auth_users.role missing"
    assert "scopes" in cols, "auth_users.scopes missing"
    assert "created_at" in cols, "auth_users.created_at missing"
    assert "last_login_at" in cols, "auth_users.last_login_at missing"
    assert "disabled_at" in cols, "auth_users.disabled_at missing"
    assert "failed_login_count" in cols, "auth_users.failed_login_count missing"
    assert "locked_until" in cols, "auth_users.locked_until missing"
    engine.dispose()


def test_revision_1_creates_refresh_tokens_table(isolated_db: str) -> None:
    """After upgrade head, refresh_tokens exists with the spec'd columns."""
    cfg = _make_alembic_config(isolated_db)
    alembic_command.upgrade(cfg, "head")

    engine = _make_sqlite_engine(isolated_db)
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA table_info(refresh_tokens)")).fetchall()
        cols = {row[1] for row in rows}

    assert "id" in cols
    assert "user_id" in cols
    assert "token_hash" in cols
    assert "family_id" in cols
    assert "expires_at" in cols
    assert "revoked_at" in cols
    assert "replaced_by" in cols
    assert "created_at" in cols
    assert "ip_first_seen" in cols
    assert "user_agent_first_seen" in cols
    engine.dispose()


def test_revision_1_email_unique_constraint(isolated_db: str) -> None:
    """Two inserts with the same email raise IntegrityError."""
    cfg = _make_alembic_config(isolated_db)
    alembic_command.upgrade(cfg, "head")

    engine = _make_sqlite_engine(isolated_db)
    user_id_1 = str(uuid.uuid4())
    user_id_2 = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO auth_users (id, email, password_hash, role, scopes, created_at) "
                "VALUES (:id, :email, 'h', 'operator', '[]', '2026-01-01 00:00:00')"
            ),
            {"id": user_id_1, "email": "dup@example.com"},
        )
    with pytest.raises(sqlalchemy.exc.IntegrityError), engine.begin() as conn:  # UNIQUE email
        conn.execute(
            text(
                "INSERT INTO auth_users (id, email, password_hash, role, scopes, created_at) "
                "VALUES (:id, :email, 'h', 'operator', '[]', '2026-01-01 00:00:00')"
            ),
            {"id": user_id_2, "email": "dup@example.com"},
        )
    engine.dispose()


def test_revision_1_token_hash_unique_constraint(isolated_db: str) -> None:
    """Two refresh_tokens rows with the same token_hash raise IntegrityError."""
    cfg = _make_alembic_config(isolated_db)
    alembic_command.upgrade(cfg, "head")

    engine = _make_sqlite_engine(isolated_db)
    user_id = str(uuid.uuid4())
    family_id = str(uuid.uuid4())
    rt_id_1 = str(uuid.uuid4())
    rt_id_2 = str(uuid.uuid4())
    with engine.begin() as conn:
        # Need an auth_users row first (FK)
        conn.execute(
            text(
                "INSERT INTO auth_users (id, email, password_hash, role, scopes, created_at) "
                "VALUES (:id, 'u@example.com', 'h', 'operator', '[]', '2026-01-01 00:00:00')"
            ),
            {"id": user_id},
        )
        conn.execute(
            text(
                "INSERT INTO refresh_tokens "
                "(id, user_id, token_hash, family_id, expires_at, created_at) "
                "VALUES (:id, :uid, 'same-hash', :fid, '2099-01-01 00:00:00', '2026-01-01 00:00:00')"
            ),
            {"id": rt_id_1, "uid": user_id, "fid": family_id},
        )
    with pytest.raises(sqlalchemy.exc.IntegrityError), engine.begin() as conn:  # UNIQUE token_hash
        conn.execute(
            text(
                "INSERT INTO refresh_tokens "
                "(id, user_id, token_hash, family_id, expires_at, created_at) "
                "VALUES (:id, :uid, 'same-hash', :fid, '2099-01-01 00:00:00', '2026-01-01 00:00:00')"
            ),
            {"id": rt_id_2, "uid": user_id, "fid": family_id},
        )
    engine.dispose()


def test_revision_1_fk_cascade_on_user_delete(isolated_db: str) -> None:
    """Deleting an auth_users row cascades to delete their refresh_tokens."""
    cfg = _make_alembic_config(isolated_db)
    alembic_command.upgrade(cfg, "head")

    engine = _make_sqlite_engine(isolated_db)
    user_id = str(uuid.uuid4())
    family_id = str(uuid.uuid4())
    rt_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO auth_users (id, email, password_hash, role, scopes, created_at) "
                "VALUES (:id, 'cascade@example.com', 'h', 'operator', '[]', '2026-01-01 00:00:00')"
            ),
            {"id": user_id},
        )
        conn.execute(
            text(
                "INSERT INTO refresh_tokens "
                "(id, user_id, token_hash, family_id, expires_at, created_at) "
                "VALUES (:id, :uid, 'h-cascade', :fid, '2099-01-01 00:00:00', '2026-01-01 00:00:00')"
            ),
            {"id": rt_id, "uid": user_id, "fid": family_id},
        )
        conn.execute(text("DELETE FROM auth_users WHERE id = :id"), {"id": user_id})

    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM refresh_tokens WHERE id = :id"), {"id": rt_id}
        ).scalar_one()
    assert count == 0, "CASCADE delete did not remove the refresh_tokens row"
    engine.dispose()


def test_revision_1_round_trip(isolated_db: str) -> None:
    """upgrade -> downgrade -> upgrade is lossless for audit_log."""
    cfg = _make_alembic_config(isolated_db)

    # baseline: 1 audit row
    engine = _make_sqlite_engine(isolated_db)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_log (timestamp, action, target, user_id, details) "
                "VALUES ('2026-01-01 12:00:00', 'BASELINE', 't', 'local', '{}')"
            )
        )
        baseline_count = conn.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one()
    assert baseline_count == 1

    alembic_command.upgrade(cfg, "head")
    alembic_command.downgrade(cfg, "base")
    alembic_command.upgrade(cfg, "head")

    with engine.connect() as conn:
        post_count = conn.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one()
        post_action = conn.execute(text("SELECT action FROM audit_log WHERE id = 1")).scalar_one()
    assert post_count == 1
    assert post_action == "BASELINE"
    engine.dispose()


# ---------------------------------------------------------------------------
# Revision 2 — extend audit_log with user_id / username / request_jwt_jti
# ---------------------------------------------------------------------------


def test_revision_2_adds_user_id_username_jti_columns(isolated_db: str) -> None:
    """After upgrade head, audit_log has the three new NULLable columns."""
    cfg = _make_alembic_config(isolated_db)
    alembic_command.upgrade(cfg, "head")

    engine = _make_sqlite_engine(isolated_db)
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA table_info(audit_log)")).fetchall()
        cols = {row[1] for row in rows}
    assert "user_id" in cols, "audit_log.user_id missing"
    assert "username" in cols, "audit_log.username missing"
    assert "request_jwt_jti" in cols, "audit_log.request_jwt_jti missing"
    engine.dispose()


def test_revision_2_backfills_legacy_username(isolated_db: str) -> None:
    """After upgrade head, pre-migration rows have username='legacy'."""
    cfg = _make_alembic_config(isolated_db)
    engine = _make_sqlite_engine(isolated_db)
    with engine.begin() as conn:
        # Insert 5 pre-migration rows (user_id='local', no username)
        for i in range(5):
            conn.execute(
                text(
                    "INSERT INTO audit_log (timestamp, action, target, user_id, details) "
                    "VALUES (:ts, 'PRE', :target, 'local', '{}')"
                ),
                {"ts": f"2026-01-{i + 1:02d} 00:00:00", "target": f"t{i}"},
            )
    alembic_command.upgrade(cfg, "head")

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT user_id, username FROM audit_log WHERE action = 'PRE'")
        ).fetchall()
    assert len(rows) == 5
    for user_id, username in rows:
        assert (
            username == "legacy"
        ), f"row user_id={user_id} username={username!r}, expected 'legacy'"
    engine.dispose()


def test_revision_2_downgrade_drops_columns_not_table(isolated_db: str) -> None:
    """Downgrade removes the new columns; the audit_log table itself remains
    with its existing rows intact (per spec §6).
    """
    cfg = _make_alembic_config(isolated_db)
    engine = _make_sqlite_engine(isolated_db)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_log (timestamp, action, target, user_id, details) "
                "VALUES ('2026-01-01 00:00:00', 'PRESERVE_ME', 't', 'local', '{}')"
            )
        )

    # Upgrade all the way (current head — includes the PR-J3.7
    # JSON-expression index migration atop the PR-J1 columns).
    alembic_command.upgrade(cfg, "head")
    # Downgrade past rev 2 — keeps rev 1 (auth_users, refresh_tokens),
    # drops the rev 2 columns. We pin the target rev explicitly so
    # the test stays correct as the migration graph grows.
    alembic_command.downgrade(cfg, "20261014000001")

    with engine.connect() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(audit_log)")).fetchall()}
        preserved = conn.execute(
            text("SELECT COUNT(*) FROM audit_log WHERE action = 'PRESERVE_ME'")
        ).scalar_one()

    assert "username" not in cols, "downgrade did not drop username"
    assert "request_jwt_jti" not in cols, "downgrade did not drop request_jwt_jti"
    # NOTE: 'user_id' predates rev 2 (it was already a column on audit_log per
    # app/models.py line 338). The downgrade should NOT remove it.
    assert "user_id" in cols, "downgrade dropped the pre-existing user_id column!"
    assert preserved == 1, "downgrade lost a pre-existing audit_log row"
    engine.dispose()


def test_revision_2_backfill_completes_under_30s_on_50k_rows(isolated_db: str) -> None:
    """Backfill performance gate: 50 000 rows → < 30 s on the test machine.

    The PR-J1 spec requires 10 000-row batches. We seed 50 000 rows so we hit
    the multi-batch code path and still keep CI fast.
    """
    cfg = _make_alembic_config(isolated_db)
    _seed_audit_rows(isolated_db, 50_000)

    engine = _make_sqlite_engine(isolated_db)
    with engine.connect() as conn:
        pre_count = conn.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one()
    assert pre_count == 50_000

    t0 = time.time()
    alembic_command.upgrade(cfg, "head")
    elapsed = time.time() - t0

    with engine.connect() as conn:
        legacy_count = conn.execute(
            text("SELECT COUNT(*) FROM audit_log WHERE username = 'legacy'")
        ).scalar_one()
    assert legacy_count == 50_000
    # Generous bound for CI variability; spec says <30s, we measure ~10-15s locally.
    assert elapsed < 30, f"backfill took {elapsed:.1f}s, exceeds 30s budget"
    engine.dispose()
