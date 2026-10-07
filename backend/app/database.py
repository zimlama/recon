"""SQLAlchemy 2 database setup.

SQLite default, swap DATABASE_URL for PostgreSQL without code changes.
Alembic handles migrations; `init_db()` creates tables on first run.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

settings = get_settings()

# Ensure data directory exists for SQLite
if settings.DATABASE_URL.startswith("sqlite"):
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if db_path and db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

# Engine — SQLite needs check_same_thread=False for multi-threaded use
_engine_kwargs: dict[str, object] = {
    "echo": settings.DATABASE_ECHO,
    "future": True,
    "pool_pre_ping": True,
}
if settings.DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine: Engine = create_engine(settings.DATABASE_URL, **_engine_kwargs)  # type: ignore[arg-type]

# Enable FK enforcement on SQLite
if settings.DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _enable_sqlite_fk(dbapi_conn: object, _conn_record: object) -> None:
        cursor = dbapi_conn.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """SQLAlchemy 2 declarative base. All ORM models inherit from this."""

    pass


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a database session, ensures close.

    Usage:
        @app.get("/items")
        def read_items(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Idempotent — safe to call on every startup.

    For schema changes, use Alembic migrations instead.
    """
    # Import all models to register them with Base.metadata
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def drop_all_tables() -> None:
    """Drop all tables. USE WITH CAUTION — for tests only."""
    from app import models  # noqa: F401

    Base.metadata.drop_all(bind=engine)
