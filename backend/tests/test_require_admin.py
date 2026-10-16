"""Tests for the hardened ``require_admin`` dependency (PR-J4).

Spec coverage (engram #1431, REQ-LEG-002 + REQ-ADM-001..006):

- ``Depends(require_admin)`` MUST 403 unless the freshly-decoded JWT
  ``role`` claim is ``"admin"``. The dep re-verifies the JWT signature
  via ``JwtKeyManager.verify()``; ``request.state.role`` is NOT trusted
  for the gate decision (REQ-ADM-001).
- Missing / malformed / unverifiable bearer token → ``TokenInvalidError``
  (401), not ``AdminForbiddenError`` (403) — auth-failure vs authz-failure
  (REQ-ADM-002).
- Dev-bypass (``state.auth_method == "dev"``) and legacy-bypass
  (``state.auth_method == "legacy"``) fallback for single-user local
  installs + the PR-J8 dual-auth window — no JWT, no 401 (REQ-ADM-003).
- DB-free boundary: ``inspect.signature(require_admin) == (request,)``
  and the module does NOT import ``app.database`` / ``sqlalchemy``
  (REQ-ADM-004).

Why direct dep calls (not HTTP): Starlette's ``BaseHTTPMiddleware``
rewraps the inner ``Request`` in a way that decouples the middleware's
``request.state`` writes from the dep's ``request.state`` reads in the
same route (verified empirically; see ``app/audit/middleware.py`` for
the contract that ``request.state`` is populated INSIDE route handlers
when paired with the audit middleware). Calling the dep directly with
a synthetic Request is the cleanest way to pin the gate's semantics.
The end-to-end JWT chain (``DualAuthMiddleware`` → state → dep → handler)
is exercised in ``test_auth_flow.py``.

Test rig (PR-J4):
- ``rsa_pem_pair`` / ``keypair_paths`` / ``jwt_keys`` fixtures mirror
  ``tests/test_auth_jwt.py`` (the canonical test-only keypair harness).
- ``_make_request(*, headers, state)`` builds a synthetic ``Request``
  with the supplied headers + state; no hard-coded ``state.role`` —
  the dep must read the freshly-decoded JWT claim.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Request
from starlette.datastructures import State

from app.auth.deps import require_admin
from app.auth.errors import (
    AdminForbiddenError,
    InvalidSinceError,
    SinceTooOldError,
    TokenInvalidError,
)
from app.auth.jwt import JwtKeyManager
from app.database import Base, engine

# ---------------------------------------------------------------------------
# Test rig — RSA keypair + JwtKeyManager + request factory
# ---------------------------------------------------------------------------


@pytest.fixture
def rsa_pem_pair() -> tuple[bytes, bytes]:
    """Generate a fresh 2048-bit RSA keypair as (private_pem, public_pem)."""
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


@pytest.fixture
def keypair_paths(
    tmp_path: Path,
    rsa_pem_pair: tuple[bytes, bytes],
) -> Iterator[tuple[Path, Path]]:
    """Write the keypair to disk and yield (priv_path, pub_path)."""
    priv, pub = rsa_pem_pair
    p = tmp_path / "priv.pem"
    pu = tmp_path / "pub.pem"
    p.write_bytes(priv)
    pu.write_bytes(pub)
    return p, pu


@pytest.fixture
def jwt_keys(keypair_paths: tuple[Path, Path]) -> JwtKeyManager:
    """A live ``JwtKeyManager`` wired to the temp keypair + settings issuer."""
    from app.config import get_settings

    priv_path, pub_path = keypair_paths
    return JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        issuer=get_settings().JWT_ISSUER,
    )


def _make_request(
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    state: dict[str, object] | None = None,
) -> Request:
    """Build a synthetic ``Request`` with the supplied headers + state.

    The dep reads both the ``Authorization`` header AND any seeded
    ``request.state`` attributes (``user_id``, ``role``, ``auth_method``).
    Tests that exercise the dev-bypass / legacy-bypass fallback seed
    ``state.auth_method``; tests that exercise the JWT path leave
    ``state`` empty and pass a real ``Authorization`` header.
    """
    scope: dict = {
        "type": "http",
        "method": "GET",
        "path": "/admin-probe",
        "headers": headers if headers is not None else [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
    }
    scope["state"] = State()
    for k, v in (state or {}).items():
        setattr(scope["state"], k, v)
    return Request(scope)


def _bearer(token: str) -> list[tuple[bytes, bytes]]:
    """Build the ``Authorization: Bearer <token>`` header pair."""
    return [(b"authorization", f"Bearer {token}".encode())]


@pytest_asyncio.fixture
async def db_ready() -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)
    yield


# ---------------------------------------------------------------------------
# T0 — Test rig collection (no functional tests yet; fixtures must collect)
# ---------------------------------------------------------------------------


def test_test_rig_fixtures_collect(jwt_keys) -> None:
    """Sanity: the new ``jwt_keys`` fixture builds a live manager."""
    assert isinstance(jwt_keys, JwtKeyManager)
    assert jwt_keys.current_kid == "k1"


def test_test_rig_request_factory_supports_empty_state() -> None:
    """``_make_request()`` with no args builds a clean request."""
    request = _make_request()
    assert request.state is not None
    assert getattr(request.state, "user_id", None) is None
    assert getattr(request.state, "role", None) is None


def test_test_rig_request_factory_supports_state() -> None:
    """``_make_request(state=...)`` seeds attributes on ``request.state``."""
    request = _make_request(state={"user_id": "u-x", "role": "operator"})
    assert request.state.user_id == "u-x"
    assert request.state.role == "operator"


def test_test_rig_request_factory_supports_headers() -> None:
    """``_make_request(headers=...)`` puts headers on the request scope."""
    request = _make_request(headers=[(b"authorization", b"Bearer abc")])
    assert request.headers.get("Authorization") == "Bearer abc"


# ---------------------------------------------------------------------------
# Pre-existing body-shape contracts (kept — they assert the 403/400 body
# shape that PR-J4 preserves). Will move to test_auth_schemas_errors.py
# in a follow-up cleanup PR.
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# T1.1 (RED → GREEN) — ``_resolve_effective_role`` helper:
#   Real admin JWT → returns ``(sub, role)`` tuple; raises
#   ``TokenInvalidError`` on any failure (and never leaks pyjwt strings).
# REQ-ADM-001 / REQ-ADM-002.
# ---------------------------------------------------------------------------


from app.auth.deps import _resolve_effective_role  # noqa: E402


@pytest.mark.asyncio
async def test_resolve_effective_role_admin_jwt_returns_sub_and_role(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.1 / T1.2 — Real admin JWT → helper returns ``(sub, role='admin')``."""
    token = jwt_keys.sign(
        {"sub": "u-admin-1", "role": "admin", "scopes": ["jobs:read"]},
        ttl_seconds=900,
    )
    request = _make_request(headers=_bearer(token))
    sub, role = _resolve_effective_role(request, jwt_keys)
    assert sub == "u-admin-1"
    assert role == "admin"


@pytest.mark.asyncio
async def test_resolve_effective_role_operator_jwt_returns_role(
    jwt_keys: JwtKeyManager,
) -> None:
    """Triangulation: operator JWT → helper returns ``(sub, role='operator')``.

    The helper MUST surface the freshly-decoded ``role``; the 403 vs 200
    decision is the caller's (``require_admin``) responsibility.
    """
    token = jwt_keys.sign(
        {"sub": "u-op-1", "role": "operator", "scopes": []},
        ttl_seconds=900,
    )
    request = _make_request(headers=_bearer(token))
    sub, role = _resolve_effective_role(request, jwt_keys)
    assert sub == "u-op-1"
    assert role == "operator"


@pytest.mark.asyncio
async def test_resolve_effective_role_missing_header_raises_token_invalid(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.3 — No ``Authorization`` header → ``TokenInvalidError`` (401)."""
    request = _make_request()  # empty headers, no state
    with pytest.raises(TokenInvalidError) as ei:
        _resolve_effective_role(request, jwt_keys)
    assert ei.value.status_code == 401
    assert ei.value.code == "token_invalid"


@pytest.mark.asyncio
async def test_resolve_effective_role_empty_bearer_raises_token_invalid(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.3 — ``Authorization: Bearer `` (empty token) → 401."""
    request = _make_request(headers=[(b"authorization", b"Bearer ")])
    with pytest.raises(TokenInvalidError):
        _resolve_effective_role(request, jwt_keys)


@pytest.mark.asyncio
async def test_resolve_effective_role_non_bearer_raises_token_invalid(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.3 — ``Authorization: Basic xyz`` → 401 (only Bearer accepted)."""
    request = _make_request(headers=[(b"authorization", b"Basic xyz")])
    with pytest.raises(TokenInvalidError):
        _resolve_effective_role(request, jwt_keys)


@pytest.mark.asyncio
async def test_resolve_effective_role_malformed_token_raises_token_invalid(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.3 — ``Authorization: Bearer aaa.bbb`` (2-segment malformed) → 401."""
    request = _make_request(headers=[(b"authorization", b"Bearer aaa.bbb")])
    with pytest.raises(TokenInvalidError):
        _resolve_effective_role(request, jwt_keys)


@pytest.mark.asyncio
async def test_resolve_effective_role_unknown_kid_raises_token_invalid(
    jwt_keys: JwtKeyManager,
    tmp_path: Path,
) -> None:
    """T1.3 — JWT signed by an unknown kid → 401, no oracle leak."""
    # Build a SECOND JwtKeyManager with its own keypair + kid that the
    # ``jwt_keys`` fixture's keyset does NOT know about. Sign a token
    # there; the test manager must reject it as ``unknown_kid`` →
    # ``TokenInvalidError``.
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    priv = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / "stranger_priv.pem"
    pub_path = tmp_path / "stranger_pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    stranger = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="stranger",
        issuer=jwt_keys._issuer,
    )
    token = stranger.sign(
        {"sub": "u-x", "role": "admin", "scopes": []},
        ttl_seconds=900,
    )
    request = _make_request(headers=_bearer(token))
    with pytest.raises(TokenInvalidError):
        _resolve_effective_role(request, jwt_keys)


@pytest.mark.asyncio
async def test_resolve_effective_role_expired_token_raises_token_invalid(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.3 — Expired JWT → 401 (well past the 5s clock-skew leeway)."""
    token = jwt_keys.sign(
        {"sub": "u-x", "role": "admin", "scopes": []},
        ttl_seconds=-100,  # 100 s past exp
    )
    request = _make_request(headers=_bearer(token))
    with pytest.raises(TokenInvalidError):
        _resolve_effective_role(request, jwt_keys)


@pytest.mark.asyncio
async def test_resolve_effective_role_tampered_signature_raises_token_invalid(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.3 — JWT with the last byte of the signature flipped → 401."""
    token = jwt_keys.sign(
        {"sub": "u-x", "role": "admin", "scopes": []},
        ttl_seconds=900,
    )
    # Tamper: flip the last char of the signature segment.
    head, mid, sig = token.split(".")
    last = sig[-1]
    replacement = "A" if last != "A" else "B"
    tampered = f"{head}.{mid}.{sig[:-1]}{replacement}"
    request = _make_request(headers=_bearer(tampered))
    with pytest.raises(TokenInvalidError):
        _resolve_effective_role(request, jwt_keys)


@pytest.mark.asyncio
async def test_resolve_effective_role_no_oracle_leak_in_error(
    jwt_keys: JwtKeyManager,
) -> None:
    """T1.3 — error body MUST NOT leak ``pyjwt`` / ``signature`` / ``audience`` / ``issuer``.

    Collapsing all pyjwt errors to ``TokenInvalidError(401, token_invalid)``
    is the anti-oracle posture (REQ-ADM-002 Scenario "oracle").
    """
    # Use a tampered signature to provoke an internal pyjwt error.
    token = jwt_keys.sign(
        {"sub": "u-x", "role": "admin", "scopes": []},
        ttl_seconds=900,
    )
    head, mid, sig = token.split(".")
    tampered = f"{head}.{mid}.{sig[:-1]}X"
    request = _make_request(headers=_bearer(tampered))
    with pytest.raises(TokenInvalidError) as ei:
        _resolve_effective_role(request, jwt_keys)
    body = ei.value.body
    flat = str(body).lower()
    for forbidden in ("pyjwt", "signature", "audience", "issuer"):
        assert forbidden not in flat, (
            f"oracle leak: {forbidden!r} appears in error body {body!r}"
        )


@pytest.mark.asyncio
async def test_resolve_effective_role_token_without_sub_raises_token_invalid(
    jwt_keys: JwtKeyManager,
) -> None:
    """A JWT signed without a ``sub`` claim → ``TokenInvalidError``.

    The verify path returns claims; if ``sub`` is missing or empty,
    the helper refuses with 401 (the same path as a missing header).
    """
    # ``JwtKeyManager.sign`` always emits a ``sub`` via ``setdefault``
    # is NOT triggered for ``sub`` (only ``iat``/``exp``/``iss``/``aud``
    # have setdefault). Build claims without ``sub`` and confirm.
    # To bypass the manager's claim auto-population we sign with an
    # explicit ``sub=""`` (empty string → falsy) and check the helper
    # rejects it.
    token = jwt_keys.sign(
        {"sub": "", "role": "admin", "scopes": []},
        ttl_seconds=900,
    )
    request = _make_request(headers=_bearer(token))
    with pytest.raises(TokenInvalidError):
        _resolve_effective_role(request, jwt_keys)


def test_get_jwt_keys_settings_fallback_when_keys_uninitialised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``get_jwt_keys`` falls back to a fresh manager from Settings.

    When ``request.app.state.jwt_keys`` is ``None`` (e.g. the lifespan
    handler did NOT preload the keys — ad-hoc test use) the dep
    constructs a fresh ``JwtKeyManager`` from ``Settings``. The
    resulting manager verifies tokens signed against the SAME settings
    keypair.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    from app.auth.deps import get_jwt_keys
    from app.config import get_settings

    priv = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / "priv.pem"
    pub_path = tmp_path / "pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    fresh = get_settings()
    monkeypatch.setattr(fresh, "JWT_PRIVATE_KEY_PATH", str(priv_path))
    monkeypatch.setattr(fresh, "JWT_PUBLIC_KEY_PATH", str(pub_path))

    # Build a Request whose scope carries the app-shaped state we want.
    app_state = State()
    # jwt_keys remains unset on app_state (None).
    scope: dict = {
        "type": "http",
        "method": "GET",
        "path": "/admin-probe",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "app": type("_StubApp", (), {"state": app_state})(),
    }
    req = Request(scope)
    mgr = get_jwt_keys(req)  # type: ignore[arg-type]
    assert isinstance(mgr, JwtKeyManager)
    # The dep cached the new manager on app.state for next call.
    assert app_state.jwt_keys is mgr


def test_get_jwt_keys_raises_when_no_keys_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When BOTH paths are unset, the dep raises ``TokenInvalidError``."""
    from app.auth.deps import get_jwt_keys
    from app.config import get_settings

    fresh = get_settings()
    monkeypatch.setattr(fresh, "JWT_PRIVATE_KEY_PATH", None)
    monkeypatch.setattr(fresh, "JWT_PUBLIC_KEY_PATH", None)

    app_state = State()
    scope: dict = {
        "type": "http",
        "method": "GET",
        "path": "/admin-probe",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "app": type("_StubApp", (), {"state": app_state})(),
    }
    req = Request(scope)
    with pytest.raises(TokenInvalidError) as ei:
        get_jwt_keys(req)  # type: ignore[arg-type]
    assert "auth subsystem not initialised" in ei.value.message


# ---------------------------------------------------------------------------
# T2.x (RED → GREEN) — ``require_admin`` re-uses the helper, NOT
# ``request.state.role``. REQ-ADM-001.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_admin_admin_jwt_returns_sub(
    jwt_keys: JwtKeyManager,
) -> None:
    """T2.1 — Real admin JWT → ``require_admin`` returns the sub claim.

    NOTE: caller invokes ``require_admin`` with the live ``jwt_keys`` so
    the dep re-verifies the bearer. No state seeding.
    """
    token = jwt_keys.sign(
        {"sub": "u-admin-1", "role": "admin", "scopes": ["jobs:read"]},
        ttl_seconds=900,
    )
    request = _make_request(headers=_bearer(token))
    user_id = require_admin(
        request=request,  # type: ignore[arg-type]
        jwt_keys=jwt_keys,
    )
    assert user_id == "u-admin-1"


@pytest.mark.asyncio
async def test_require_admin_operator_jwt_returns_403(
    jwt_keys: JwtKeyManager,
) -> None:
    """T2.1 — Real operator JWT → ``AdminForbiddenError`` (403)."""
    token = jwt_keys.sign(
        {"sub": "u-op-1", "role": "operator", "scopes": []},
        ttl_seconds=900,
    )
    request = _make_request(headers=_bearer(token))
    with pytest.raises(AdminForbiddenError) as ei:
        require_admin(
            request=request,  # type: ignore[arg-type]
            jwt_keys=jwt_keys,
        )
    body = ei.value.body
    assert body["error"] == "forbidden"
    assert body["required_role"] == "admin"


@pytest.mark.asyncio
async def test_require_admin_missing_header_returns_401(
    jwt_keys: JwtKeyManager,
) -> None:
    """T2.1 — Missing Authorization header → ``TokenInvalidError`` (401)."""
    request = _make_request()  # no headers, no state
    with pytest.raises(TokenInvalidError):
        require_admin(
            request=request,  # type: ignore[arg-type]
            jwt_keys=jwt_keys,
        )


@pytest.mark.asyncio
async def test_require_admin_drift_state_admin_jwt_operator_returns_403(
    jwt_keys: JwtKeyManager,
) -> None:
    """T2.3 — ``state.role='admin'`` BUT JWT ``role='operator'`` → 403.

    Drift is caught: the dep trusts the freshly-decoded JWT claim, not
    the cached state.
    """
    token = jwt_keys.sign(
        {"sub": "u-x", "role": "operator", "scopes": []},
        ttl_seconds=900,
    )
    # Seeded state claims admin; JWT says operator — dep must trust JWT.
    request = _make_request(
        headers=_bearer(token),
        state={"role": "admin", "user_id": "spoofed"},
    )
    with pytest.raises(AdminForbiddenError):
        require_admin(
            request=request,  # type: ignore[arg-type]
            jwt_keys=jwt_keys,
        )


@pytest.mark.asyncio
async def test_require_admin_drift_state_operator_jwt_admin_returns_200(
    jwt_keys: JwtKeyManager,
) -> None:
    """T2.3 — ``state.role='operator'`` BUT JWT ``role='admin'`` → 200.

    Inverse drift: cached state claims operator; the dep must NOT use
    that for the authz decision (no implicit demotion by state).
    """
    token = jwt_keys.sign(
        {"sub": "u-admin-2", "role": "admin", "scopes": []},
        ttl_seconds=900,
    )
    request = _make_request(
        headers=_bearer(token),
        state={"role": "operator", "user_id": "spoofed"},
    )
    user_id = require_admin(
        request=request,  # type: ignore[arg-type]
        jwt_keys=jwt_keys,
    )
    assert user_id == "u-admin-2"


# ---------------------------------------------------------------------------
# T2.x — ``get_current_user_id`` also re-verifies (no cache trust).
# ---------------------------------------------------------------------------


from app.auth.deps import get_current_user_id  # noqa: E402


@pytest.mark.asyncio
async def test_get_current_user_id_returns_sub_from_jwt(
    jwt_keys: JwtKeyManager,
) -> None:
    """``get_current_user_id`` returns the freshly-decoded ``sub``.

    Even when ``state.user_id`` is seeded with a different value, the
    dep re-verifies the JWT and returns the JWT's ``sub``.
    """
    token = jwt_keys.sign(
        {"sub": "u-jwt-sub", "role": "admin", "scopes": []},
        ttl_seconds=900,
    )
    request = _make_request(
        headers=_bearer(token),
        state={"user_id": "state-cached", "role": "admin"},
    )
    user_id = get_current_user_id(
        request=request,  # type: ignore[arg-type]
        jwt_keys=jwt_keys,
    )
    assert user_id == "u-jwt-sub"


@pytest.mark.asyncio
async def test_get_current_user_id_missing_header_raises_401(
    jwt_keys: JwtKeyManager,
) -> None:
    """No ``Authorization`` → ``get_current_user_id`` raises ``TokenInvalidError``."""
    request = _make_request(state={"user_id": "state-cached"})
    with pytest.raises(TokenInvalidError):
        get_current_user_id(
            request=request,  # type: ignore[arg-type]
            jwt_keys=jwt_keys,
        )


# ---------------------------------------------------------------------------
# T3.x (RED → GREEN) — Dev-bypass + legacy-bypass fallback.
# REQ-ADM-003.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_admin_dev_bypass_admin_no_jwt_returns_200(
    jwt_keys: JwtKeyManager,
) -> None:
    """T3.1 — ``state.auth_method='dev'`` + no JWT + ``state.role='admin'`` → 200, returns ``"local"``.

    Single-user local installs (no RECON_API_KEY, no JWT keys,
    ``APP_ENV != 'production'``) match the dev-bypass branch in
    ``DualAuthMiddleware`` and must NOT 401.
    """
    request = _make_request(
        state={
            "auth_method": "dev",
            "user_id": "local",
            "role": "admin",
        },
    )
    user_id = require_admin(
        request=request,  # type: ignore[arg-type]
        jwt_keys=jwt_keys,
    )
    assert user_id == "local"


@pytest.mark.asyncio
async def test_require_admin_dev_bypass_operator_no_jwt_returns_403(
    jwt_keys: JwtKeyManager,
) -> None:
    """T3.1 — ``state.auth_method='dev'`` + ``state.role='operator'`` → 403.

    Dev-bypass fallback preserves the ``role == 'admin'`` gate. An
    operator-role dev-bypass request must still 403.
    """
    request = _make_request(
        state={
            "auth_method": "dev",
            "user_id": "local",
            "role": "operator",
        },
    )
    with pytest.raises(AdminForbiddenError):
        require_admin(
            request=request,  # type: ignore[arg-type]
            jwt_keys=jwt_keys,
        )


@pytest.mark.asyncio
async def test_require_admin_legacy_bypass_admin_no_jwt_returns_200(
    jwt_keys: JwtKeyManager,
) -> None:
    """T3.1 — ``state.auth_method='legacy'`` + ``state.role='admin'`` + no JWT → 200.

    The PR-J8 dual-auth window routes ``RECON_API_KEY``-bearing requests
    through ``DualAuthMiddleware``'s legacy branch (sets
    ``state.auth_method='legacy'``). Those requests must still pass
    ``require_admin`` until the legacy window closes.
    """
    request = _make_request(
        state={
            "auth_method": "legacy",
            "user_id": "local",
            "role": "admin",
        },
    )
    user_id = require_admin(
        request=request,  # type: ignore[arg-type]
        jwt_keys=jwt_keys,
    )
    assert user_id == "local"


@pytest.mark.asyncio
async def test_require_admin_jwt_auth_method_no_jwt_returns_401(
    jwt_keys: JwtKeyManager,
) -> None:
    """T3.1 — ``state.auth_method='jwt'`` + no JWT → 401.

    The ``jwt`` path is NOT in the fallback set; the dep must insist on
    a real bearer when the middleware says it tried to verify one.
    """
    request = _make_request(
        state={"auth_method": "jwt", "user_id": "spoofed", "role": "admin"},
    )
    with pytest.raises(TokenInvalidError):
        require_admin(
            request=request,  # type: ignore[arg-type]
            jwt_keys=jwt_keys,
        )


@pytest.mark.asyncio
async def test_require_admin_missing_auth_method_no_jwt_returns_401(
    jwt_keys: JwtKeyManager,
) -> None:
    """T3.1 — ``state.auth_method`` missing (None) + no JWT → 401."""
    request = _make_request(state={"role": "admin"})  # no auth_method
    with pytest.raises(TokenInvalidError):
        require_admin(
            request=request,  # type: ignore[arg-type]
            jwt_keys=jwt_keys,
        )


# ---------------------------------------------------------------------------
# T4 — DB-free boundary. REQ-ADM-004.
# Parametrised static gate: ``require_admin`` signature is exactly
# ``(request,)`` (the ``jwt_keys`` arg has a default via ``Depends`` so
# ``inspect`` reports only the explicit positional). The module does
# NOT import ``app.database``, ``app.auth.models``, ``sqlalchemy``, or
# ``sqlalchemy.orm``.
# ---------------------------------------------------------------------------


def test_require_admin_signature_has_only_request() -> None:
    """``require_admin`` is DB-free — no DB session in the dep chain.

    The dep signature is exactly ``(request, jwt_keys=Depends(...))`` —
    no DB session injection. ``jwt_keys`` is a FastAPI Depends (so the
    caller does not pass it explicitly), but ``inspect.signature``
    surfaces it as a keyword-only argument with a default.
    """
    import inspect

    sig = inspect.signature(require_admin)
    params = list(sig.parameters)
    # Allow-list: exactly ``request`` + ``jwt_keys``. Any other arg means
    # we've re-introduced a DB session or similar dep injection.
    assert params == ["request", "jwt_keys"], (
        f"require_admin signature changed unexpectedly: {params}"
    )


def test_deps_module_has_no_db_imports() -> None:
    """``app.auth.deps`` MUST NOT import any DB / SQLAlchemy layer.

    REQ-ADM-004 boundary: the dep is DB-free. The DB-backed
    ``auth_users.role`` lookup is deferred to PR-J4.x.
    """
    import inspect

    import app.auth.deps as deps_mod

    source = inspect.getsource(deps_mod)
    forbidden_modules = (
        "app.database",
        "app.auth.models",
        "sqlalchemy",
        "sqlalchemy.orm",
        "from sqlalchemy",
        "import sqlalchemy",
    )
    for forbidden in forbidden_modules:
        assert forbidden not in source, (
            f"DB boundary leak: {forbidden!r} appears in deps.py"
        )


# ---------------------------------------------------------------------------
# T5.3 — schemas.py docstring cleanup. REQ-ADM-005.
# ``LegacyUsageStatsResponse`` MUST NOT mention ``X-Admin-Gate-Best-Effort``,
# ``best-effort``, or ``_BEST_EFFORT_`` anywhere in its docstring.
# ---------------------------------------------------------------------------


def test_legacy_usage_stats_response_docstring_no_best_effort_mention() -> None:
    """T5.3 — ``LegacyUsageStatsResponse`` docstring has no best-effort caveat."""
    import inspect

    from app.auth.schemas import LegacyUsageStatsResponse

    docstring = inspect.getdoc(LegacyUsageStatsResponse) or ""
    flat = docstring.lower()
    for forbidden in (
        "x-admin-gate-best-effort",
        "best-effort",
        "_best_effort_",
    ):
        assert forbidden not in flat, (
            f"docstring still mentions {forbidden!r}: {docstring!r}"
        )
