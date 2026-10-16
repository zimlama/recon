"""Fail-loud Settings validators for PR-J1 auth secrets.

These tests pin the contract that ``PEPPER_SECRET`` and ``REFRESH_HASH_KEY``
MUST be set (>=32 bytes) when ``APP_ENV=production``. In dev/staging/test
the operator may run without a key — the same leniency the existing
``PERSON_DOSSIER_ENCRYPTION_KEY`` validator applies.

Audit finding (PR-J1 R1 Risk review, B-2):

    ``PasswordService._read_pepper()`` returns "" when ``PEPPER_SECRET`` is
    unset. Without a Settings-level validator the deployment manifests
    can be published empty and the process boots happily with an empty
    pepper. A DB theft then becomes brute-forceable at full argon2 speed
    because the attacker no longer has to crack the pepper + hash pair.

Reproducer for the B-2 gap (BEFORE the fix):

    APP_ENV=production python -c "from app.config import Settings; Settings()"
    # exits 0, PEPPER_SECRET == ""

Reproducer (AFTER the fix):

    APP_ENV=production python -c "from app.config import Settings; Settings()"
    # pydantic.ValidationError: PEPPER_SECRET must be set in production ...
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings

# Fernet-shaped 32-byte b64 key, used to satisfy the unrelated
# PERSON_DOSSIER_ENCRYPTION_KEY validator so the production tests can
# isolate the PEP* and RHK* assertions. This mirrors test_config.py.
_VALID_FERNET_KEY = "ZmFrZS1mZXJuZXQta2V5LXdlLWluc3BlY3QtY2Y="  # 32B b64 fake

# A 32-byte pepper / refresh key — long enough to satisfy the >=32 check
# when we want to assert "production with a valid value is allowed".
_VALID_PEPPER_32B = "p" * 32
_VALID_RHK_32B = "k" * 32


# ---------------------------------------------------------------------------
# PEPPER_SECRET
# ---------------------------------------------------------------------------


def test_pepper_secret_empty_in_production_raises() -> None:
    """PEP-PEP-1: ``PEPPER_SECRET=""`` MUST raise in production.

    R1 Risk scenario 8 (FAIL before fix, MUST pass after).
    """
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            PEPPER_SECRET="",
            PERSON_DOSSIER_ENCRYPTION_KEY=_VALID_FERNET_KEY,
        )
    msg = str(exc_info.value)
    assert "PEPPER_SECRET" in msg, f"expected error mentioning PEPPER_SECRET, got: {msg[:300]}"
    assert "production" in msg.lower(), f"expected error mentioning 'production', got: {msg[:300]}"


def test_pepper_secret_too_short_raises() -> None:
    """PEP-PEP-2: a non-empty value below 32 bytes MUST raise.

    31 bytes is one short of the recommended minimum and would silently
    weaken the pepper. Fail-loud at boot, not at first login.
    """
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            PEPPER_SECRET="x" * 31,
            PERSON_DOSSIER_ENCRYPTION_KEY=_VALID_FERNET_KEY,
        )
    assert "PEPPER_SECRET" in str(exc_info.value)
    assert "32" in str(exc_info.value), "error message should mention the 32-byte minimum"


def test_pepper_secret_empty_in_development_allowed() -> None:
    """PEP-PEP-3: dev/staging/test may run with PEPPER_SECRET unset.

    Matches the operator-friendly posture of PERSON_DOSSIER_ENCRYPTION_KEY.
    The PasswordService accepts an empty pepper at test-time so unit tests
    in test_auth_password.py can run without a fixture.
    """
    # development
    s = Settings(APP_ENV="development", PEPPER_SECRET="")
    assert s.PEPPER_SECRET == ""
    # staging
    s = Settings(APP_ENV="staging", PEPPER_SECRET="")
    assert s.PEPPER_SECRET == ""
    # test
    s = Settings(APP_ENV="test", PEPPER_SECRET="")
    assert s.PEPPER_SECRET == ""


def test_pepper_secret_32_bytes_in_production_ok() -> None:
    """PEP-PEP-4: a valid 32-byte pepper in production MUST be accepted.

    REFRESH_HASH_KEY is also set so the cascaded validator does not
    pre-empt this assertion with an unrelated REFRESH_HASH_KEY error.
    """
    s = Settings(
        APP_ENV="production",
        PEPPER_SECRET=_VALID_PEPPER_32B,
        REFRESH_HASH_KEY=_VALID_RHK_32B,
        PERSON_DOSSIER_ENCRYPTION_KEY=_VALID_FERNET_KEY,
    )
    assert s.PEPPER_SECRET == _VALID_PEPPER_32B


# ---------------------------------------------------------------------------
# REFRESH_HASH_KEY (same contract — separate field, separate validator)
# ---------------------------------------------------------------------------


def test_refresh_hash_key_empty_in_production_raises() -> None:
    """PEP-RHK-1: ``REFRESH_HASH_KEY=""`` MUST raise in production.

    Refresh token hashes are stored at rest. If the HMAC key is unset, the
    stored hash reverts to an unsalted SHA-256, which is publicly
    brute-forceable for a 256-bit-entropy refresh token. A leaked DB then
    leaks live refresh tokens.
    """
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            REFRESH_HASH_KEY="",
            PERSON_DOSSIER_ENCRYPTION_KEY=_VALID_FERNET_KEY,
        )
    msg = str(exc_info.value)
    assert (
        "REFRESH_HASH_KEY" in msg
    ), f"expected error mentioning REFRESH_HASH_KEY, got: {msg[:300]}"
    assert "production" in msg.lower(), f"expected error mentioning 'production', got: {msg[:300]}"


def test_refresh_hash_key_too_short_raises() -> None:
    """PEP-RHK-2: <32 bytes MUST raise in production."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            REFRESH_HASH_KEY="x" * 31,
            PERSON_DOSSIER_ENCRYPTION_KEY=_VALID_FERNET_KEY,
        )
    assert "REFRESH_HASH_KEY" in str(exc_info.value)
    assert "32" in str(exc_info.value)


def test_refresh_hash_key_empty_in_development_allowed() -> None:
    """PEP-RHK-3: dev/staging/test may run without REFRESH_HASH_KEY."""
    s = Settings(APP_ENV="development", REFRESH_HASH_KEY="")
    assert s.REFRESH_HASH_KEY == ""
    s = Settings(APP_ENV="staging", REFRESH_HASH_KEY="")
    assert s.REFRESH_HASH_KEY == ""
    s = Settings(APP_ENV="test", REFRESH_HASH_KEY="")
    assert s.REFRESH_HASH_KEY == ""


def test_refresh_hash_key_32_bytes_in_production_ok() -> None:
    """PEP-RHK-4: a valid 32-byte key in production MUST be accepted.

    PEPPER_SECRET is also set so the cascaded validator does not
    pre-empt this assertion with an unrelated PEPPER_SECRET error.
    """
    s = Settings(
        APP_ENV="production",
        PEPPER_SECRET=_VALID_PEPPER_32B,
        REFRESH_HASH_KEY=_VALID_RHK_32B,
        PERSON_DOSSIER_ENCRYPTION_KEY=_VALID_FERNET_KEY,
    )
    assert s.REFRESH_HASH_KEY == _VALID_RHK_32B


# ---------------------------------------------------------------------------
# Both validators fail together when both secrets are missing
# ---------------------------------------------------------------------------


def test_both_pepper_and_refresh_missing_raises_with_both_names() -> None:
    """PEP-BOTH-1: when both secrets are empty in production, the error
    must mention BOTH field names (not just the first one Pydantic
    encounters). This lets the operator fix the manifest in one pass.
    """
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            APP_ENV="production",
            PEPPER_SECRET="",
            REFRESH_HASH_KEY="",
            PERSON_DOSSIER_ENCRYPTION_KEY=_VALID_FERNET_KEY,
        )
    msg = str(exc_info.value)
    assert "PEPPER_SECRET" in msg, f"missing PEPPER_SECRET in: {msg[:400]}"
    assert "REFRESH_HASH_KEY" in msg, f"missing REFRESH_HASH_KEY in: {msg[:400]}"
