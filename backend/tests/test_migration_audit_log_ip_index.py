"""Tests for the PR-J3.7 functional-index migration.

Spec coverage (engram #1431, REQ-LEG-008 / NFR-LEG-005):

- ``20261016000003_add_audit_log_ip_index`` adds the partial JSON-
  expression index that keeps ``GROUP BY json_extract(details,
  '$.ip')`` sub-millisecond past 1M legacy rows.
- Reversible: ``alembic downgrade -1`` drops the index.

This migration stacks on top of rev ``20261014000002`` (PR-J1) which
already added the ``username`` column. We boot a transient SQLite,
run upgrade + downgrade, and assert via ``PRAGMA index_list``.

Docstring on the migration calls out the SQLite + Postgres duality —
Postgres uses identical ``json_extract`` syntax; MySQL would need a
virtual generated column (excluded per spec NFR-LEG-005).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, inspect, text

from alembic import command as alembic_command


def _index_names(engine, table: str) -> set[str]:
    """Return the set of index names attached to ``table``.

    SQLAlchemy's ``inspect.get_indexes`` does NOT reflect
    JSON-expression-based indexes (it warns on expression
    indexes). Falls back to ``PRAGMA index_list`` which
    always reflects all indexes by name regardless of the
    expression form.
    """

    # SQLAlchemy path first; if it can't see the expression index
    # we fall back to PRAGMA. Both are read-only and fast.
    try:
        names = {idx["name"] for idx in inspect(engine).get_indexes(table)}
    except Exception:
        names = set()
    # Always include PRAGMA-based names so expression indexes show up.
    with engine.connect() as conn:
        rows = conn.execute(
            text(f"PRAGMA index_list('{table}')")
        ).all()
    for row in rows:
        # row[1] is the index name per PRAGMA index_list column order.
        names.add(str(row[1]))
    return names


def _make_sqlite_engine(db_url: str):
    engine = create_engine(db_url)
    return engine


def _make_alembic_config(db_url: str, backend: Path) -> AlembicConfig:
    cfg = AlembicConfig(str(backend / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def _run_with_env_override(target_db_url: str, action):
    """Run an alembic command with ``DATABASE_URL`` env override.

    Mirrors ``test_alembic_identity_map._run_with_target_db``: clears
    ``get_settings.cache_clear()`` so the alembic ``env.py`` resolves
    the new URL on next import-time + runtime read.
    """
    import os

    from app.config import get_settings

    prior = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = target_db_url
    get_settings.cache_clear()
    try:
        action()
    finally:
        if prior is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = prior
        get_settings.cache_clear()


def _seed_pre_migration_schema(db_url: str) -> None:
    """Pre-create the audit_log table WITHOUT the PR-J1 columns so rev
    ``20261014000002`` can add them, then rev ``20261016000003`` (PR-J3.7)
    adds the JSON-expression index.

    Mirrors the pre-PR-J1 schema — same columns / indexes that
    ``app.models.AuditLog`` declares minus the three PR-J1 columns.
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


@pytest.fixture
def tmp_db(tmp_path: Path) -> Iterator[str]:
    """Yield a fresh SQLite URL with the PR-J1 pre-state."""

    db_path = tmp_path / "pr_j3_7_migration.db"
    if db_path.exists():
        db_path.unlink()
    target_url = f"sqlite:///{db_path}"
    _seed_pre_migration_schema(target_url)
    yield target_url
    if db_path.exists():
        db_path.unlink()


def test_audit_log_ip_index_upgrade_creates_index(tmp_db: str) -> None:
    """``alembic upgrade head`` creates the partial JSON-expression index."""

    backend = Path(__file__).resolve().parents[1]
    cfg = _make_alembic_config(tmp_db, backend)

    # Pre-condition: index must NOT exist.
    engine = _make_sqlite_engine(tmp_db)
    pre = _index_names(engine, "audit_log")
    assert "ix_audit_log_legacy_ip_ts" not in pre

    def _run():
        alembic_command.upgrade(cfg, "head")

    _run_with_env_override(tmp_db, _run)

    post = _index_names(engine, "audit_log")
    assert "ix_audit_log_legacy_ip_ts" in post, (
        "ix_audit_log_legacy_ip_ts should exist after upgrade; "
        f"got indexes {sorted(post)!r}"
    )

    engine.dispose()


def test_audit_log_ip_index_downgrade_drops_index(tmp_db: str) -> None:
    """``alembic downgrade -1`` reverses the index cleanly."""

    backend = Path(__file__).resolve().parents[1]
    cfg = _make_alembic_config(tmp_db, backend)

    def _up():
        alembic_command.upgrade(cfg, "head")

    _run_with_env_override(tmp_db, _up)

    engine = _make_sqlite_engine(tmp_db)
    pre = _index_names(engine, "audit_log")
    assert "ix_audit_log_legacy_ip_ts" in pre

    def _down():
        alembic_command.downgrade(cfg, "-1")

    _run_with_env_override(tmp_db, _down)

    post = _index_names(engine, "audit_log")
    assert "ix_audit_log_legacy_ip_ts" not in post, (
        f"ix_audit_log_legacy_ip_ts should be gone after downgrade -1; "
        f"got indexes {sorted(post)!r}"
    )

    engine.dispose()


def test_audit_log_ip_index_re_creates_cleanly(tmp_db: str) -> None:
    """Upgrade → downgrade → upgrade round-trip leaves the index present."""

    backend = Path(__file__).resolve().parents[1]
    cfg = _make_alembic_config(tmp_db, backend)

    def _run_cycle():
        alembic_command.upgrade(cfg, "head")
        alembic_command.downgrade(cfg, "-1")
        alembic_command.upgrade(cfg, "head")

    _run_with_env_override(tmp_db, _run_cycle)

    engine = _make_sqlite_engine(tmp_db)
    post = _index_names(engine, "audit_log")
    assert "ix_audit_log_legacy_ip_ts" in post

    engine.dispose()
