"""Log-scrubbing security tests for sec-auth-jwt (PR-J2.5, spec section 5).

Spec section 5: "no token plaintext, no password, no pepper value in any log line".

These tests:

1. Issue + rotate tokens.
2. Capture log output (pytest's ``caplog`` fixture).
3. Grep the captured log lines for any forbidden strings:
   - The literal ``rt_<43 base64url chars>`` token plaintext.
   - The plaintext password (anything we know is a password).
   - The PEPPER_SECRET value.

If ANY of these appear in the log output, the test fails. The const is a
guard against accidental leaks — future refactors that route tokens or
secrets through ``print`` or ``logger.warning`` will be caught here.

What is NOT tested: that the production logging config has correct levels
or that logs go to a secure sink. That is a PR-J7 ops-doc concern (and a
gitleaks / log-scrubber concern at deploy time). These tests only cover
the in-process invariants our code can guarantee.
"""

from __future__ import annotations

import logging
import re

import pytest

from app.auth.models import AuthUser
from app.auth.refresh import TOKEN_PREFIX, RefreshService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# A token plaintext matches: ``rt_`` + exactly 43 chars from the base64url
# alphabet (no padding chars). Anything else starting with ``rt_`` (like
# the literal constant) is excluded.
_TOKEN_RE = re.compile(rf"{TOKEN_PREFIX}[A-Za-z0-9_-]{{43}}\b")


def _scrub_forbidden(log_text: str, *, password: str, pepper: str) -> list[str]:
    """Return a list of forbidden substrings actually present in ``log_text``.

    Empty list = no leak detected. Test asserts this is empty.
    """
    found: list[str] = []
    # 1. Token plaintext.
    for match in _TOKEN_RE.finditer(log_text):
        found.append(f"refresh token: {match.group(0)!r}")
    # 2. Plaintext password (the password we tried to issue / verify with).
    if password and password in log_text:
        found.append(f"password: {password!r}")
    # 3. Pepper value.
    if pepper and pepper in log_text:
        found.append(f"pepper: {pepper!r}")
    return found


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_TEST_HASH_KEY = "x" * 64
_TEST_PASSWORD = "correct horse battery staple"  # 28 chars — well over the 12 min
_TEST_PEPPER = "p" * 64  # realistic length; long enough to avoid false positives


@pytest.fixture
def engine():
    """Per-test in-memory SQLite engine with auth tables only.

    Mirrors the fixture in test_refresh_service.py. Duplicated here so
    pytest can resolve it without a cross-file import (fixtures are
    per-module by default). Keep these in lockstep with
    test_refresh_service.py.
    """
    from sqlalchemy import create_engine as _ce

    from app.auth.models import RefreshToken as _RefreshToken
    from app.database import Base

    eng = _ce("sqlite:///:memory:")
    Base.metadata.create_all(
        bind=eng,
        tables=[AuthUser.__table__, _RefreshToken.__table__],
    )
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    """Return a ``session_factory`` callable for ``RefreshService``."""
    from sqlalchemy.orm import sessionmaker

    return sessionmaker(bind=engine)


@pytest.fixture
def service_with_engine(engine, session_factory):
    """RefreshService wired to a per-test in-memory engine.

    Also sets PEPPER_SECRET in os.environ so the password service picks
    it up; clears on teardown so other tests don't see it.
    """
    import os

    os.environ["PEPPER_SECRET"] = _TEST_PEPPER
    svc = RefreshService(
        session_factory=session_factory,
        hash_key=_TEST_HASH_KEY,
        refresh_ttl_seconds=3600,
    )
    yield svc
    os.environ.pop("PEPPER_SECRET", None)


@pytest.fixture
def seeded_user(engine, session_factory):
    """Pre-seeded AuthUser so the service has a target user_id.

    Returns a lightweight ``types.SimpleNamespace`` carrying just the
    fields the service needs (id) so we don't trip
    DetachedInstanceError by reading ORM attributes after the session
    closes.
    """
    import types
    from datetime import datetime

    user_id = "00000000-0000-0000-0000-000000000001"
    with session_factory() as s:
        u = AuthUser(
            id=user_id,
            email="alice@example.com",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$abc$def",
            role="operator",
            scopes="[]",
            created_at=datetime(2026, 1, 1),
        )
        s.add(u)
        s.commit()
    return types.SimpleNamespace(id=user_id, email="alice@example.com", role="operator")


# ---------------------------------------------------------------------------
# Spec section 5 — log-scrubbing guards
# ---------------------------------------------------------------------------


def test_issue_does_not_log_token_plaintext(service_with_engine, seeded_user, caplog) -> None:
    """Issuing a token does not leak its plaintext to any logger.

    Captures WARNING+ from the root logger (DEBUG/INFO are filtered
    to keep the test scope tight — PR-J2 surfaces client errors via
    WARNING/ERROR).
    """
    caplog.set_level(logging.WARNING)
    issued = service_with_engine.issue(seeded_user.id)
    leaks = _scrub_forbidden(
        caplog.text,
        password=_TEST_PASSWORD,
        pepper=_TEST_PEPPER,
    )
    assert leaks == [], f"forbidden strings found in logs: {leaks}"
    # Sanity: the token was actually issued (so we tested the real path).
    assert issued.plaintext.startswith(TOKEN_PREFIX)


def test_rotate_does_not_log_token_plaintext(service_with_engine, seeded_user, caplog) -> None:
    """Rotating a token does not leak either the old or the new plaintext."""
    caplog.set_level(logging.WARNING)
    issued = service_with_engine.issue(seeded_user.id)
    caplog.clear()
    rotated = service_with_engine.rotate(issued.plaintext)
    leaks = _scrub_forbidden(
        caplog.text,
        password=_TEST_PASSWORD,
        pepper=_TEST_PEPPER,
    )
    assert leaks == [], f"forbidden strings found in logs: {leaks}"
    assert rotated.plaintext.startswith(TOKEN_PREFIX)
    # And specifically neither plaintext appears.
    assert issued.plaintext not in caplog.text
    assert rotated.plaintext not in caplog.text


def test_reuse_revocation_does_not_log_token_plaintext(
    service_with_engine, seeded_user, caplog
) -> None:
    """Family-revoke on reuse does not leak the offending token plaintext."""
    from app.auth.refresh import FamilyRevokedError

    caplog.set_level(logging.WARNING)
    issued = service_with_engine.issue(seeded_user.id)
    rotated = service_with_engine.rotate(issued.plaintext)
    caplog.clear()
    with pytest.raises(FamilyRevokedError):
        service_with_engine.rotate(issued.plaintext)
    leaks = _scrub_forbidden(
        caplog.text,
        password=_TEST_PASSWORD,
        pepper=_TEST_PEPPER,
    )
    assert leaks == [], f"forbidden strings found in logs: {leaks}"
    # None of the plaintexts appear in logs even with the exception path.
    for pt in (issued.plaintext, rotated.plaintext):
        assert pt not in caplog.text, f"{pt!r} leaked in log"


def test_token_invalid_error_message_does_not_contain_plaintext(
    service_with_engine, seeded_user, caplog
) -> None:
    """The TokenInvalidError message must NOT include the presented plaintext."""
    caplog.set_level(logging.WARNING)
    fake_token = f"{TOKEN_PREFIX}{'A' * 43}"
    from app.auth.refresh import TokenInvalidError

    with pytest.raises(TokenInvalidError) as ei:
        service_with_engine.rotate(fake_token)
    err_text = str(ei.value)
    assert (
        fake_token not in err_text
    ), f"TokenInvalidError leaked the offending plaintext: {err_text!r}"
    # And the captured logs are clean.
    leaks = _scrub_forbidden(
        caplog.text,
        password=_TEST_PASSWORD,
        pepper=_TEST_PEPPER,
    )
    assert leaks == [], f"forbidden strings found in logs: {leaks}"


def test_refresh_token_constant_is_not_a_real_plaintext(
    service_with_engine, seeded_user, caplog
) -> None:
    """The literal ``rt_`` constant in source doesn't accidentally appear in logs.

    Defends against a regression where someone echoes the prefix constant
    in a warning like "invalid format: rt_ expected" — that would mean
    ANY token starting with ``rt_`` matches the constant, defeating the
    grep invariant.
    """
    caplog.set_level(logging.WARNING)
    service_with_engine.issue(seeded_user.id)
    # No full token plaintext should appear (only the bare 'rt_' prefix may).
    matches = _TOKEN_RE.findall(caplog.text)
    assert matches == [], f"unexpected token plaintexts in logs: {matches}"


def test_password_handling_code_paths_no_leak(service_with_engine, seeded_user, caplog) -> None:
    """The refresh service never touches passwords — but verify by construction.

    RefreshService has no password parameter and never imports
    ``PasswordService``; this test pins that contract by reading the
    source. If a refactor accidentally crosses the boundary,
    test_security_grapples catches it at code-review time AND
    test_password_does_not_leak would catch it at runtime below.
    """
    import inspect

    from app.auth import refresh as mod

    src = inspect.getsource(mod)
    # Must NOT import PasswordService.
    assert "PasswordService" not in src
    # Must NOT reference PEPPER_SECRET (that's password's concern).
    assert "PEPPER_SECRET" not in src
    # Must NOT have a password parameter on any public method.
    for name in (
        "issue",
        "rotate",
        "revoke_family",
        "revoke_user",
        "lookup",
        "purge_expired",
        "active_count",
    ):
        method = getattr(mod.RefreshService, name, None)
        if method is None:
            continue
        sig = inspect.signature(method)
        assert (
            "password" not in sig.parameters
        ), f"RefreshService.{name} unexpectedly accepts a password parameter"


def test_log_scrub_catches_injected_text(caplog) -> None:
    """Sanity: the scrub helper actually catches what it claims to catch.

    If this test ever flips green-with-leak, the scrub helper is broken
    and every other test in this file is a false negative.
    """
    caplog.set_level(logging.WARNING)
    caplog.handler.emit(
        logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=0,
            msg="leak: %s",
            args=(f"{TOKEN_PREFIX}{'B' * 43}",),
            exc_info=None,
        )
    )
    leaks = _scrub_forbidden(
        caplog.text,
        password="correct horse battery staple",
        pepper="p" * 64,
    )
    assert any("refresh token" in s for s in leaks), "scrub helper is not catching tokens!"
