"""Tests for the hardened ``require_admin`` dependency (PR-J3.7).

Spec coverage (engram #1431, REQ-LEG-002): ``Depends(require_admin)``
MUST 403 unless ``request.state.role == "admin"``. The pre-existing
stub returned ``user_id`` blindly and trusted the role to whichever
caller cached it in ``request.state`` — fine when ``DualAuthMiddleware``
populated it, but semantically empty.

Cases pinned here:

1. ``state.role='admin'`` and a present ``user_id`` → ``require_admin``
   returns the user_id (handler runs).
2. ``state.role='operator'`` → ``AdminForbiddenError`` raised
   (status 403, code ``forbidden``, body carries ``required_role``).
3. ``state.role=None`` → ``AdminForbiddenError`` raised (no implicit
   admin-grant when role is unknown).
4. Unit-level: ``_AdminForbiddenError`` / ``_SinceTooOldError`` /
   ``_InvalidSinceError`` body shapes (no HTTP round trip).

Why direct dep calls (not HTTP): Starlette's BaseHTTPMiddleware
rebuilds the inner Request from scope in a way that decouples the
middleware's ``request.state`` writes from the dep's ``request.state``
in the same route (verified empirically; see ``app/audit/middleware.py``
for the contract that ``request.state`` is populated INSIDE route
handlers when paired with the audit middleware). Calling the dep
directly with a synthetic Request is the cleanest way to pin the
gate's semantics; the end-to-end authentication chain (DualAuth →
state → dep → handler) is exercised in ``test_auth_flow.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from fastapi import Request

from app.auth.deps import require_admin
from app.auth.errors import (
    AdminForbiddenError,
    InvalidSinceError,
    SinceTooOldError,
)
from app.database import Base, engine


def _make_request(
    *,
    user_id: str | None,
    role: str | None,
) -> Request:
    """Build a synthetic ``Request`` with the supplied state seeded.

    Stubs ``scope["state"]`` (Starlette's ``State`` cache) directly so
    the dep's ``getattr(request.state, "user_id", None)`` reads the
    values we want. Avoids the entire ``BaseHTTPMiddleware`` rewrap
    problem (the dep reads the same state the route handler does)."""

    scope: dict = {
        "type": "http",
        "method": "GET",
        "path": "/admin-probe",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
    }
    # Seed a fresh State() so both the dep's request and any inner
    # rewrap see the same data.
    from starlette.datastructures import State  # local import — keeps
    # the test file's top-level imports light.

    scope["state"] = State()
    if user_id is not None:
        scope["state"].user_id = user_id
    if role is not None:
        scope["state"].role = role

    return Request(scope)


@pytest_asyncio.fixture
async def db_ready() -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)
    yield


@pytest.mark.asyncio
async def test_require_admin_happy_path_returns_user_id() -> None:
    """``state.role='admin'`` + present ``user_id`` → handler runs."""

    request = _make_request(user_id="u-1", role="admin")
    user_id = require_admin(
        request=request,  # type: ignore[arg-type]
        user_id="u-1",
    )
    assert user_id == "u-1"


@pytest.mark.asyncio
async def test_require_admin_raises_admin_forbidden_for_operator() -> None:
    """``state.role='operator'`` → ``AdminForbiddenError`` raised."""

    request = _make_request(user_id="u-2", role="operator")
    with pytest.raises(AdminForbiddenError) as excinfo:
        require_admin(
            request=request,  # type: ignore[arg-type]
            user_id="u-2",
        )

    err = excinfo.value
    assert err.status_code == 403
    body = err.body
    assert body["error"] == "forbidden"
    assert body["required_role"] == "admin"
    assert "message" in body


@pytest.mark.asyncio
async def test_require_admin_raises_when_role_missing() -> None:
    """``state.role=None`` → ``AdminForbiddenError`` (no implicit grant)."""

    request = _make_request(user_id="u-3", role=None)
    with pytest.raises(AdminForbiddenError):
        require_admin(
            request=request,  # type: ignore[arg-type]
            user_id="u-3",
        )


def test_admin_forbidden_error_body() -> None:
    """Unit-level: ``AdminForbiddenError`` body shape is the contract."""

    err = AdminForbiddenError()
    body = err.body
    assert body == {
        "error": "forbidden",
        "message": "Admin role required",
        "required_role": "admin",
    }
    http = err.to_http_response()
    assert http[0] == 403
    assert "WWW-Authenticate" not in http[1]  # not a 401


def test_since_too_old_error_body() -> None:
    """Unit-level: ``SinceTooOldError`` carries ``max_lookback_days``."""

    err = SinceTooOldError(max_lookback_days=365)
    assert err.status_code == 400
    body = err.body
    assert body["error"] == "since_too_old"
    assert body["max_lookback_days"] == 365
    assert "message" in body


def test_invalid_since_error_body() -> None:
    """Unit-level: ``InvalidSinceError`` carries the Pydantic detail."""

    err = InvalidSinceError(detail="Input should be a valid datetime")
    assert err.status_code == 400
    body = err.body
    assert body["error"] == "invalid_since"
    assert body["detail"] == "Input should be a valid datetime"
