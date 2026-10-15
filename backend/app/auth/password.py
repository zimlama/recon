"""PasswordService — argon2id with server-side pepper (PR-J1, sec-auth-jwt).

This module is intentionally small and pure: every method is a
``staticmethod`` on ``PasswordService`` so it can be called without
instantiation, and there is no global mutable state. The only inputs are
the password, the stored hash, and (optionally) the pepper string. The
only outputs are PHC strings or booleans.

Spec coverage (engram #1371):

- §4 INV-8 — p95 verify < 300 ms on the CI baseline.
  The OWASP 2024 params (m=64MiB, t=3, p=4) take ~80-150 ms per verify.
- §4 INV-9 — pepper composition. ``PEPPER_SECRET`` is read at hash + verify
  time. A leaked DB alone cannot be cracked because the attacker still
  needs the pepper from the env. Rotation invalidates every stored hash.
- §4 INV-10 — first-admin bootstrap. (Handled in PR-J4; this module only
  owns the crypto primitive, not the CLI command.)

Threat model recap:

- Offline DB theft: without the pepper, an attacker with the auth_users
  table cannot run argon2 brute-force at scale; the pepper adds a server
  secret they do not have. This is defense-in-depth — the *primary*
  defence is argon2id's memory-hardness.
- Online credential stuffing: rate-limit + lockout (PR-J3 / PR-J5).
- Password reuse: handled by users, not by the service.
"""

from __future__ import annotations

import os

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

# OWASP 2024 minimums for argon2id (spec §7):
#   time_cost=3, memory_cost=65536 KiB (64 MiB), parallelism=4.
_TIME_COST = 3
_MEMORY_COST = 65_536  # KiB
_PARALLELISM = 4

# Spec §1.1: LoginRequest.min_password_length=12. Enforced at hash time so
# callers (CLI, /auth/login router) cannot store a sub-12-char password
# even if their own validation is bypassed by a refactor.
MIN_PASSWORD_LENGTH = 12


class WeakPasswordError(ValueError):
    """Raised when a password does not meet the strength policy.

    Carries ``min_length`` so the CLI / API layer can surface a useful
    error to the operator (e.g. "password too short, need ≥12 chars").
    """

    def __init__(self, message: str, min_length: int = MIN_PASSWORD_LENGTH) -> None:
        super().__init__(message)
        self.min_length = min_length


# Single shared hasher instance. argon2-cffi caches its internal state
# so reuse across calls is the recommended pattern.
_PHCR = PasswordHasher(
    time_cost=_TIME_COST,
    memory_cost=_MEMORY_COST,
    parallelism=_PARALLELISM,
)


class PasswordService:
    """Static service. All methods are pure functions modulo the OS env.

    No constructor state. Tests can monkeypatch ``PEPPER_SECRET`` between
    calls without touching any module-level globals (the env is read on
    each invocation).
    """

    # ---- Hashing -----------------------------------------------------------

    @staticmethod
    def hash(
        password: str,
        *,
        pepper: str | None = None,
        time_cost: int = _TIME_COST,
        memory_cost: int = _MEMORY_COST,
        parallelism: int = _PARALLELISM,
    ) -> str:
        """Return an argon2id PHC string of ``password`` + pepper.

        Parameters ``time_cost``, ``memory_cost``, ``parallelism`` are
        exposed only so ``needs_rehash`` can verify a hash minted with old
        parameters. Production callers MUST NOT override them — that would
        silently weaken the hash.
        """
        _check_password_strength(password)

        phc_hasher = (
            _PHCR
            if (time_cost, memory_cost, parallelism) == (_TIME_COST, _MEMORY_COST, _PARALLELISM)
            else PasswordHasher(
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
        )
        composed = password + (pepper if pepper is not None else _read_pepper())
        return phc_hasher.hash(composed)

    # ---- Verifying ---------------------------------------------------------

    @staticmethod
    def verify(password: str, stored_hash: str, *, pepper: str | None = None) -> bool:
        """Constant-time verify of ``password`` against ``stored_hash``.

        Returns False on ANY error (mismatch, malformed hash, empty input).
        NEVER raises. The boolean return is the ONLY signal — there is no
        way for a caller to distinguish "wrong password" from "malformed
        hash" from outside this module. That is intentional, to avoid user
        enumeration / format oracles.
        """
        if not isinstance(password, str) or not isinstance(stored_hash, str):
            return False
        if not password or not stored_hash:
            return False
        composed = password + (pepper if pepper is not None else _read_pepper())
        try:
            _PHCR.verify(stored_hash, composed)
            return True
        except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
            return False

    # ---- Rehash-on-login trigger ------------------------------------------

    @staticmethod
    def needs_rehash(stored_hash: str) -> bool:
        """True iff ``stored_hash`` was minted with weaker parameters than
        the current policy.

        Caller is expected to call this after a successful ``verify`` and,
        if True, replace the stored hash with a freshly-minted one on the
        next credential rotation. This is the standard argon2-cffi pattern
        for bumping parameters without invalidating every user at once.
        """
        if not isinstance(stored_hash, str) or not stored_hash:
            return False
        try:
            return _PHCR.check_needs_rehash(stored_hash)
        except (InvalidHashError, ValueError):
            # Malformed hash — caller has bigger problems; do not raise.
            return False


# ---------------------------------------------------------------------------
# Internal helpers (NOT exported — see test_module_exports_expected_symbols)
# ---------------------------------------------------------------------------


def _read_pepper() -> str:
    """Read ``PEPPER_SECRET`` from the environment.

    Empty string is allowed at test-time so unit tests don't need to set up
    a fixture for every test. Production deployments MUST set this in the
    deployment manifest — a missing pepper produces a hash that still works
    but is no longer defense-in-depth. The ``Settings._validate_pepper_secret``
    field validator (``backend/app/config.py``) raises
    ``pydantic.ValidationError`` at boot when ``APP_ENV=production`` and the
    value is empty or below 32 bytes; see
    ``tests/test_settings_pepper_secret.py`` for the contract.
    """
    return os.environ.get("PEPPER_SECRET", "")


def _check_password_strength(password: str) -> None:
    """Enforce ``MIN_PASSWORD_LENGTH`` at the service layer."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"password too short: must be at least {MIN_PASSWORD_LENGTH} characters"
        )
