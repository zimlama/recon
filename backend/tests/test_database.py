"""Tests for the database setup."""

from __future__ import annotations

from app.database import Base, SessionLocal, engine, init_db
from app.models import Job


def test_engine_creation() -> None:
    """Engine is created and usable."""
    assert engine is not None


def test_init_db_creates_tables() -> None:
    """init_db creates the expected tables."""
    init_db()
    # Check that the Job table exists
    assert "jobs" in Base.metadata.tables


def test_session_local_works() -> None:
    """SessionLocal produces a working session."""
    db = SessionLocal()
    try:
        # Should be able to query the Job table
        result = db.query(Job).count()
        assert isinstance(result, int)
    finally:
        db.close()
