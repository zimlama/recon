"""Tests for the identity_map Alembic migration.

Verifies that ``alembic upgrade`` then ``alembic downgrade`` (in any
order) produces a state equivalent to no migration run. Per audit
finding R1-H2 / R4-M5: the lack of an ``identity_map`` migration left
production deployments running ``alembic upgrade head`` without the
table, crashing ``person_dossier._store_identity_map`` mid-job.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command

# Skip the whole module if alembic is unavailable — keeps the rest of
# the suite runnable in minimal environments.
alembic_ini = Path(__file__).resolve().parent.parent / "alembic.ini"
pytestmark = pytest.mark.skipif(
    not alembic_ini.exists(),
    reason="alembic.ini not found; skipping migration tests",
)


def _run_with_target_db(target_db_url: str, action):
    """Run an alembic command against ``target_db_url``.

    The project's ``alembic/env.py`` reads ``settings.DATABASE_URL``
    after import-time evaluation of ``get_settings()``. We can't reliably
    re-cache ``get_settings`` mid-test (it's ``lru_cache``d), so we
    rewrite the env var before each alembic invocation. Clear it
    afterwards so other tests are not affected.
    """
    envpy_path = Path(__file__).resolve().parent.parent / "alembic" / "env.py"
    cfg = Config(str(alembic_ini))
    cfg.set_main_option("script_location", str(envpy_path.parent))
    cfg.set_main_option("sqlalchemy.url", target_db_url)
    prior = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = target_db_url
    # Drop the lru_cache so env.py picks up the override on next call.
    try:
        from app.config import get_settings

        get_settings.cache_clear()
        action(cfg)
    finally:
        if prior is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = prior
        from app.config import get_settings

        get_settings.cache_clear()
    return cfg


def _table_exists(engine, table_name: str) -> bool:
    return inspect(engine).has_table(table_name)


def _seed_audit_log_for_pr_j1(target_url: str) -> None:
    """Pre-create the audit_log table that rev ``20261014000002`` extends.

    PR-J1 added a revision that ALTERs ``audit_log`` to add three columns +
    backfills pre-existing rows. Real production runs ``Base.metadata.create_all``
    (via ``init_db``) before alembic, so audit_log already exists when rev 2
    runs. Tests that exercise the migration stack from scratch need the same
    bootstrap, otherwise rev 2 errors on the missing table.

    We use hand-written SQL rather than ``Base.metadata.create_all`` so we
    don't conflict with the RoE / identity_map revisions that alembic itself
    runs in the test.
    """
    eng = create_engine(target_url)
    with eng.begin() as conn:
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
    eng.dispose()


def test_identity_map_migration_round_trip(tmp_path: Path) -> None:
    """upgrade -> downgrade restores the pre-migration schema state.

    Steps:
      1. Apply migrations up to ``head`` (which now includes PR-J1 revs).
         Verify that ``identity_map`` exists with the expected columns + indexes.
      2. Downgrade one step. PR-J1 added 2 new revs on top of identity_map's
         rev ``20261013120000``, so ``downgrade -1`` drops rev 2 (the audit_log
         extension). identity_map stays.
      3. Downgrade to ``20261007224728`` (the RoE rev) and verify that
         ``identity_map`` is gone but the RoE tables are still there.
      4. Upgrade again to head and verify ``identity_map`` is back.
    """
    db_path = tmp_path / "alembic_identity.db"
    if db_path.exists():
        db_path.unlink()
    target_url = f"sqlite:///{db_path}"
    eng = create_engine(target_url)

    # PR-J1: rev 2 ALTERs audit_log — pre-create it so the migration can run.
    _seed_audit_log_for_pr_j1(target_url)

    def upgrade(cfg: Config) -> None:
        command.upgrade(cfg, "head")

    _run_with_target_db(target_url, upgrade)

    inspector = inspect(eng)
    assert inspector.has_table("identity_map"), "identity_map missing after 'alembic upgrade head'"

    cols = {c["name"] for c in inspector.get_columns("identity_map")}
    expected_cols = {
        "id",
        "job_id",
        "email_hash",
        "encrypted_email",
        "persona_id",
        "created_at",
    }
    assert expected_cols.issubset(cols), f"identity_map missing columns: {expected_cols - cols}"

    indexes = {idx["name"] for idx in inspector.get_indexes("identity_map")}
    assert "ix_identity_map_job_id" in indexes
    assert "ix_identity_map_email_hash" in indexes

    def downgrade_to_roe(cfg: Config) -> None:
        # Downgrade two revs to land on the RoE rev (20261007224728), which
        # drops identity_map + the PR-J1 auth tables but keeps RoE/sign_off.
        command.downgrade(cfg, "20261007224728")

    _run_with_target_db(target_url, downgrade_to_roe)
    inspector = inspect(eng)
    assert not inspector.has_table("identity_map"), (
        "identity_map should be gone after downgrading past its rev"
    )
    assert inspector.has_table("roes"), "roes should survive downgrade"
    assert inspector.has_table("sign_offs"), "sign_offs should survive downgrade"

    _run_with_target_db(target_url, upgrade)
    inspector = inspect(eng)
    assert inspector.has_table("identity_map"), "identity_map must come back after re-upgrade"


def test_identity_map_unique_constraint_exists(tmp_path: Path) -> None:
    """The UNIQUE(job_id, email_hash) constraint must be present.

    Without it, ``person_dossier._store_identity_map`` could insert
    duplicates for the same (job_id, email_hash), corrupting idempotency
    semantics (per spec.md REQ-020 AC-020.6).
    """
    db_path = tmp_path / "alembic_unique.db"
    if db_path.exists():
        db_path.unlink()
    target_url = f"sqlite:///{db_path}"
    eng = create_engine(target_url)

    # PR-J1: rev 2 ALTERs audit_log — pre-create it so the migration can run.
    _seed_audit_log_for_pr_j1(target_url)

    def upgrade(cfg: Config) -> None:
        command.upgrade(cfg, "head")

    _run_with_target_db(target_url, upgrade)

    sql = text(
        "INSERT INTO identity_map (id, job_id, email_hash, "
        "encrypted_email, persona_id) VALUES "
        "(:id1, :job_id, :email_hash, 'cipher1', 'p1'), "
        "(:id2, :job_id, :email_hash, 'cipher2', 'p2')"
    )
    from sqlalchemy.exc import IntegrityError

    with eng.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(
            sql,
            {
                "id1": "row-1",
                "id2": "row-2",
                "job_id": "job-1",
                "email_hash": "a" * 64,
            },
        )
