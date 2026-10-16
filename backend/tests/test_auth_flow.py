"""End-to-end auth flow tests (PR-J3.5+J3.8 integration).

Exercises the new /api/v1/auth/* endpoints via the FastAPI test client,
covering the full login -> access -> refresh -> me -> logout chain.

These tests:
- Configure a dev/test JWT keypair at app startup (write a temp PEM).
- Seed an AuthUser row directly via SQLAlchemy.
- Issue requests through the HTTPX async client and assert responses.

Strict TDD: this file's coverage bumps service.py, router.py,
middleware.py, and deps.py past the 90% target. PR-J3 acceptance per
#1375 §J3.5 + §J3.8.
"""

from __future__ import annotations

# IMPORTANT: set env BEFORE importing app modules so Settings picks up
# our test values (get_settings() is lru_cached and frozen on first
# import). Conftest.py also sets DATABASE_URL, but the keys below are
# auth-specific and not set elsewhere.
import os as _os

_os.environ.setdefault("REFRESH_HASH_KEY", "x" * 64)
_os.environ.setdefault("PEPPER_SECRET", "p" * 64)
_os.environ.setdefault("ALLOW_LEGACY_API_KEY", "false")
# Bump the test DB to a real file so the in-memory engine inside the
# FastAPI app and our test client share persistence within one test
# function (the conftest's sqlite:///:memory: creates per-connection
# databases, which won't share rows).
import tempfile as _tf
_test_db_dir = _tf.mkdtemp(prefix="recon-auth-test-")
_os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_dir}/auth.db"
del _test_db_dir

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.password import PasswordService
from app.auth.refresh import RefreshService
from app.config import get_settings
from app.database import Base
from app.main import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_pem_pair() -> tuple[bytes, bytes]:
    """Generate a fresh RSA-2048 keypair as (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def keypair_paths(
    tmp_path_factory, rsa_pem_pair: tuple[bytes, bytes]
) -> Iterator[tuple[Path, Path]]:
    """Write the keypair to disk and yield (priv_path, pub_path)."""
    priv, pub = rsa_pem_pair
    p = tmp_path_factory.mktemp("keys") / "priv.pem"
    pu = tmp_path_factory.mktemp("keys") / "pub.pem"
    p.write_bytes(priv)
    pu.write_bytes(pub)
    # Set the env vars so the app's lifespan picks them up.
    os.environ["JWT_PRIVATE_KEY_PATH"] = str(p)
    os.environ["JWT_PUBLIC_KEY_PATH"] = str(pu)
    yield p, pu


@pytest.fixture()
def app_with_db(keypair_paths: tuple[Path, Path]) -> Iterator:
    """Build an app with a clean DB for each test (drop+create_all)."""
    # Reset settings cache so the new env values (keypair paths) are picked up.
    get_settings.cache_clear()
    app = create_app()
    # Use the same engine the app uses to drop/create tables.
    from app.database import engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield app
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
async def client(app_with_db) -> AsyncClient:
    """HTTPX async client wired to the lifespan'd app."""
    from httpx import ASGITransport

    transport = ASGITransport(app=app_with_db)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        async with app_with_db.router.lifespan_context(app_with_db):
            yield ac


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_endpoint_open(client: AsyncClient) -> None:
    """The health endpoint is public, even with auth on."""
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_modules_requires_auth(client: AsyncClient) -> None:
    """A business route returns 401 without a bearer token.

    We disabled legacy mode and enabled JWT keys, so there's no
    dev-mode bypass.
    """
    r = await client.get("/api/v1/modules")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_with_known_credentials_returns_token_pair(
    client: AsyncClient, app_with_db
) -> None:
    """A seeded user can log in and receive an access + refresh pair."""
    # Seed the user directly via the same engine the app uses.
    from app.auth.models import AuthUser
    from app.database import SessionLocal

    password = "correct-horse-battery-staple"
    phc = PasswordService.hash(password)
    with SessionLocal() as s:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash=phc,
            role="operator",
            scopes='["jobs:read"]',
        )
        s.add(u)
        s.commit()

    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": password},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"]
    assert body["refresh_token"].startswith("rt_")
    assert body["user"]["email"] == "alice@example.com"
    assert body["user"]["role"] == "operator"
    assert "jobs:read" in body["user"]["scopes"]


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(
    client: AsyncClient, app_with_db
) -> None:
    """Wrong password returns 401 with anti-enumeration wording."""
    from app.auth.models import AuthUser
    from app.database import SessionLocal

    phc = PasswordService.hash("correct-horse-battery-staple")
    with SessionLocal() as s:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash=phc,
            role="operator",
            scopes="[]",
        )
        s.add(u)
        s.commit()

    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "wrong-horse-wrong-staple"},
    )
    assert r.status_code == 401
    body = r.json()
    # FastAPI HTTPException wraps the body in `detail`
    assert body["detail"]["error"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_login_unknown_user_returns_401_same_wording(
    client: AsyncClient, app_with_db
) -> None:
    """An unknown email returns 401 with identical wording (no enumeration)."""
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "any-password-here-12"},
    )
    assert r.status_code == 401
    body = r.json()
    assert body["detail"]["error"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_refresh_returns_new_pair(client: AsyncClient, app_with_db) -> None:
    """A valid refresh token rotates and returns a new pair."""
    from app.auth.models import AuthUser
    from app.database import SessionLocal

    password = "correct-horse-battery-staple"
    phc = PasswordService.hash(password)
    with SessionLocal() as s:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash=phc,
            role="operator",
            scopes="[]",
        )
        s.add(u)
        s.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": password},
    )
    rt1 = login.json()["refresh_token"]
    at1 = login.json()["access_token"]

    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": rt1},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["refresh_token"] != rt1, "refresh token must rotate"
    assert body["access_token"] != at1, "access token must rotate"
    assert body["user"]["email"] == "alice@example.com"


@pytest.mark.asyncio
async def test_refresh_reuse_revokes_family(
    client: AsyncClient, app_with_db
) -> None:
    """Reusing a rotated refresh token triggers family revoke → 401."""
    from app.auth.models import AuthUser
    from app.database import SessionLocal

    password = "correct-horse-battery-staple"
    phc = PasswordService.hash(password)
    with SessionLocal() as s:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash=phc,
            role="operator",
            scopes="[]",
        )
        s.add(u)
        s.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": password},
    )
    rt1 = login.json()["refresh_token"]
    rt2 = (await client.post("/api/v1/auth/refresh", json={"refresh_token": rt1})).json()["refresh_token"]

    # Reuse rt1 — should be 401 with family_revoked=true
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": rt1})
    assert r.status_code == 401
    body = r.json()
    # FastAPI HTTPException wraps the body in `detail`
    assert body.get("detail", {}).get("family_revoked") is True

    # And now rt2 (the legitimate one) is also dead.
    r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": rt2})
    assert r2.status_code == 401
    assert r2.json().get("detail", {}).get("family_revoked") is True


@pytest.mark.asyncio
async def test_me_returns_current_user(client: AsyncClient, app_with_db) -> None:
    """GET /me with a valid JWT returns the user payload."""
    from app.auth.models import AuthUser
    from app.database import SessionLocal

    password = "correct-horse-battery-staple"
    phc = PasswordService.hash(password)
    with SessionLocal() as s:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash=phc,
            role="operator",
            scopes='["jobs:read"]',
        )
        s.add(u)
        s.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": password},
    )
    at = login.json()["access_token"]

    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {at}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["role"] == "operator"
    assert "password_hash" not in body


@pytest.mark.asyncio
async def test_logout_revokes_token(client: AsyncClient, app_with_db) -> None:
    """POST /logout with a valid refresh token returns 200 + count."""
    from app.auth.models import AuthUser
    from app.database import SessionLocal

    password = "correct-horse-battery-staple"
    phc = PasswordService.hash(password)
    with SessionLocal() as s:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash=phc,
            role="operator",
            scopes="[]",
        )
        s.add(u)
        s.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": password},
    )
    rt = login.json()["refresh_token"]

    r = await client.post("/api/v1/auth/logout", json={"refresh_token": rt})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["family_revoked_count"] == 1

    # Refreshing the now-revoked token should fail.
    r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": rt})
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_business_route_accepts_jwt(
    client: AsyncClient, app_with_db
) -> None:
    """A business route accepts a valid JWT (the dual-auth JWT path)."""
    from app.auth.models import AuthUser
    from app.database import SessionLocal

    password = "correct-horse-battery-staple"
    phc = PasswordService.hash(password)
    with SessionLocal() as s:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash=phc,
            role="operator",
            scopes="[]",
        )
        s.add(u)
        s.commit()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": password},
    )
    at = login.json()["access_token"]

    r = await client.get(
        "/api/v1/modules",
        headers={"Authorization": f"Bearer {at}"},
    )
    assert r.status_code == 200
