"""Tests for the Settings / config module."""

from __future__ import annotations

import pytest

from app.config import Settings, get_settings


def test_settings_load_from_env() -> None:
    """Settings can be instantiated."""
    s = Settings()
    assert s.LOG_LEVEL in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    assert s.APP_ENV in ("development", "staging", "production", "test")


def test_settings_cors_origins_parsed() -> None:
    """CORS origins string is parsed into a list."""
    s = Settings(CORS_ORIGINS="http://a.com, http://b.com , http://c.com")
    assert s.cors_origins_list == ["http://a.com", "http://b.com", "http://c.com"]


def test_settings_has_ai_key_detects_placeholder() -> None:
    """has_ai_key returns False for placeholder values."""
    s = Settings(MINIMAX_API_KEY="sk-minimax-replace-with-real-key")
    assert s.has_ai_key is False

    s2 = Settings(MINIMAX_API_KEY="sk-real-key-12345")
    assert s2.has_ai_key is True


def test_settings_is_production() -> None:
    """is_production is True only when APP_ENV is production."""
    # Provide a non-empty key so the production-mode validator passes —
    # see test_encryption_key_required_in_production for the missing-key path.
    s = Settings(
        APP_ENV="production",
        PERSON_DOSSIER_ENCRYPTION_KEY="ZmFrZS1mZXJuZXQta2V5LXdlLWluc3BlY3QtY2Y=",
    )
    assert s.is_production is True

    s2 = Settings(APP_ENV="development")
    assert s2.is_production is False


def test_settings_cached() -> None:
    """get_settings returns the same instance (LRU cached)."""
    a = get_settings()
    b = get_settings()
    assert a is b


def test_encryption_key_required_in_production() -> None:
    """PERSON_DOSSIER_ENCRYPTION_KEY is required when APP_ENV=production.

    Audit finding R1-M1 / R4-M2: a deployment with the env var unset in
    production silently skipped identity_map rows. Raising at boot
    keeps the "encrypted at rest" contract from being silently broken.
    """
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        Settings(APP_ENV="production", PERSON_DOSSIER_ENCRYPTION_KEY=None)
    assert "PERSON_DOSSIER_ENCRYPTION_KEY" in str(exc_info.value)


def test_encryption_key_optional_in_dev() -> None:
    """In dev/staging/test the operator may run without the encryption key.

    Running without a key in non-production is supported: ``person_dossier``
    logs per-affected-hash and the dossier is still emitted. The Settings
    load must NOT raise.
    """
    s = Settings(APP_ENV="development", PERSON_DOSSIER_ENCRYPTION_KEY=None)
    assert s.PERSON_DOSSIER_ENCRYPTION_KEY is None

    s2 = Settings(APP_ENV="staging", PERSON_DOSSIER_ENCRYPTION_KEY=None)
    assert s2.PERSON_DOSSIER_ENCRYPTION_KEY is None


def test_encryption_key_present_in_production_is_accepted() -> None:
    """When APP_ENV=production AND the key is set, Settings load succeeds."""
    # Fernet.generate_key() returns a URL-safe base64 32-byte key.
    # We use a value-shaped valid one — value parsing happens lazily in
    # `encryption.encrypt_email()`; Settings only checks that *some*
    # value is present in production.
    s = Settings(
        APP_ENV="production",
        PERSON_DOSSIER_ENCRYPTION_KEY="ZmFrZS1mZXJuZXQta2V5LXdlLWluc3BlY3QtY2Y=",  # 32B b64 fake
    )
    assert s.PERSON_DOSSIER_ENCRYPTION_KEY.startswith("ZmFrZS")
