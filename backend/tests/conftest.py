"""Pytest fixtures: in-memory DB, test client, mock LLM."""

from __future__ import annotations

import os

# Set test env BEFORE importing the app
# Use a per-process tempfile for the DB so connections share the same
# schema (the per-connection semantics of sqlite:///:memory: break
# auth-table visibility across handler / seed connections).
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

_test_db_dir = tempfile.mkdtemp(prefix="recon-conftest-db-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_test_db_dir}/conftest.db")
os.environ.setdefault("MINIMAX_API_KEY", "test-dummy-key")
os.environ.setdefault("MINIMAX_BASE_URL", "http://localhost:9999/v1")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("LOG_LEVEL", "DEBUG")
os.environ.setdefault("APP_ENV", "test")

# Auth-specific (PR-J3.5+J3.8). Set here so they're in env before
# get_settings() is first called and cached.
os.environ.setdefault("REFRESH_HASH_KEY", "x" * 64)
os.environ.setdefault("PEPPER_SECRET", "p" * 64)
os.environ.setdefault("ALLOW_LEGACY_API_KEY", "false")

# Ensure data dirs exist
Path("./data").mkdir(parents=True, exist_ok=True)
Path("./data/handoffs").mkdir(parents=True, exist_ok=True)
Path("./data/reports").mkdir(parents=True, exist_ok=True)
Path("./data/audit").mkdir(parents=True, exist_ok=True)

from app.config import get_settings  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402

settings = get_settings()


@pytest_asyncio.fixture
async def db() -> AsyncIterator:
    """In-memory SQLite session with fresh tables per test.

    Note: we drop_all BEFORE create_all to ensure a clean slate even if
    the engine was previously populated by another test.
    """
    from sqlalchemy.ext.asyncio import (  # noqa: F401
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    # Use sync engine for tests (simpler)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """HTTP test client."""
    # Import inside fixture to avoid circular issues
    from app.main import app

    # Init DB tables before tests (drop first to ensure clean state)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    # Cleanup
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def mock_llm_response() -> dict:
    """Sample LDMValidationResult for testing."""
    return {
        "verdicts": [
            {
                "value": "api.example.com",
                "verdict": "CONFIRMED",
                "priority": "HIGH",
                "confidence": 0.95,
                "reasoning": "Public-facing API with confirmed DNS resolution and clean history.",
                "enrichment": {"tech_hint": "Express"},
            }
        ],
        "summary": "Found 1 confirmed subdomain with high priority for next phase.",
        "recommended_action": "CONTINUE",
        "recommended_next_module_chain": ["port_scanning"],
    }


@pytest.fixture
def sample_target() -> str:
    """Sample target domain for tests."""
    return "example.com"
