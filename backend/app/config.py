"""Application configuration loaded from environment variables.

Single source of truth for runtime config. Reads from `.env` file at backend
root (loaded via python-dotenv before pydantic-settings parses).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings. All values come from env vars or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- LLM provider (MiniMax M3, OpenAI-compatible) ----
    MINIMAX_API_KEY: str = Field(
        default="sk-minimax-not-configured",
        description="MiniMax M3 API key. Required for AI validation.",
    )
    MINIMAX_BASE_URL: str = Field(
        default="https://api.minimaxi.com/v1",
        description="MiniMax M3 API base URL.",
    )
    MINIMAX_MODEL: str = Field(
        default="MiniMax-M3",
        description="MiniMax M3 model identifier.",
    )
    MINIMAX_TIMEOUT_SECONDS: int = Field(default=60, ge=1, le=300)
    MINIMAX_MAX_RETRIES: int = Field(default=3, ge=0, le=10)

    # ---- Database ----
    DATABASE_URL: str = Field(
        default="sqlite:///./data/recon.db",
        description="SQLAlchemy database URL. SQLite by default.",
    )
    DATABASE_ECHO: bool = Field(default=False, description="Echo SQL statements")

    # ---- Application ----
    SECRET_KEY: str = Field(
        default="change-me-in-production",
        description="Application secret. Must be changed in production.",
    )
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    APP_ENV: Literal["development", "staging", "production", "test"] = "development"
    CORS_ORIGINS: str = Field(
        default="http://localhost:5173,http://localhost:8080",
        description="Comma-separated allowed CORS origins.",
    )

    # ---- API authentication (Bearer token, closes audit finding C1) ----
    RECON_API_KEY: str | None = Field(
        default=None,
        description=(
            "Bearer token for API auth. If unset, all routes are open "
            "(dev mode). If set, clients must send "
            "'Authorization: Bearer <RECON_API_KEY>' on every request."
        ),
    )

    # ---- Rate limiting ----
    RATE_LIMIT_RECON_RPS: int = Field(default=10, ge=1, le=1000)
    RATE_LIMIT_RECON_BURST: int = Field(default=20, ge=1, le=10000)

    # ---- Optional API keys (Tier 2 modules) ----
    SHODAN_API_KEY: str | None = None
    CENSYS_API_ID: str | None = None
    CENSYS_API_SECRET: str | None = None
    HUNTER_API_KEY: str | None = None
    SERP_API_KEY: str | None = None
    GITHUB_TOKEN: str | None = None
    HIBP_API_KEY: str | None = None

    # ---- Paths ----
    DATA_DIR: str = Field(default="./data", description="Base data directory")
    HANDOFFS_DIR: str = Field(default="./data/handoffs")
    REPORTS_DIR: str = Field(default="./data/reports")
    AUDIT_DIR: str = Field(default="./data/audit")
    ARTIFACTS_DIR: str = Field(default="./data/artifacts")

    # ---- Feature flags ----
    AI_VALIDATION_ENABLED: bool = Field(default=True)
    HANDSHAKE_AUTO_GENERATE: bool = Field(default=True)
    AUDIT_LOGGING_ENABLED: bool = Field(default=True)

    @field_validator("CORS_ORIGINS")
    @classmethod
    def _validate_cors(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("CORS_ORIGINS cannot be empty")
        return v.strip()

    @property
    def cors_origins_list(self) -> list[str]:
        """CORS origins as a list."""
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        """True if running in production environment."""
        return self.APP_ENV == "production"

    @property
    def has_ai_key(self) -> bool:
        """True if a real (non-placeholder) MiniMax API key is configured."""
        return self.MINIMAX_API_KEY not in (
            "",
            "sk-minimax-not-configured",
            "sk-minimax-replace-with-real-key",
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached Settings instance.

    Cached because pydantic-settings does a one-time read from env + .env.
    Use this function in FastAPI dependencies: `Depends(get_settings)`.
    """
    return Settings()  # type: ignore[call-arg]
