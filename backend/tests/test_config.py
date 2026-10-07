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
    s = Settings(APP_ENV="production")
    assert s.is_production is True

    s2 = Settings(APP_ENV="development")
    assert s2.is_production is False


def test_settings_cached() -> None:
    """get_settings returns the same instance (LRU cached)."""
    a = get_settings()
    b = get_settings()
    assert a is b
