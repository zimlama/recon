"""Application configuration loaded from environment variables.

Single source of truth for runtime config. Reads from `.env` file at backend
root (loaded via python-dotenv before pydantic-settings parses).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

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

    # ---- LLM provider (MiniMax M3.1-Flash-Preview, Anthropic Messages API) ----
    # The client speaks the Anthropic Messages API against MiniMax's
    # Anthropic-compatible endpoint. The same code also works against
    # the Anthropic API directly or a local gateway by overriding
    # MINIMAX_BASE_URL and MINIMAX_API_KEY.
    # Default model is M3.1-Flash-Preview (1M context, M Plan). For
    # pay-as-you-go accounts, set MINIMAX_MODEL=MiniMax-M3 instead.
    MINIMAX_API_KEY: str = Field(
        default="sk-minimax-not-configured",
        description="MiniMax API key (M Plan Subscription Key or pay-as-you-go API Key).",
    )
    MINIMAX_BASE_URL: str = Field(
        default="https://api.minimax.io/anthropic/v1",
        description="Anthropic-compatible base URL. Default points to MiniMax; override for Anthropic direct or a local gateway.",
    )
    MINIMAX_MODEL: str = Field(
        default="MiniMax-M3.1-Flash-Preview",
        description="Model identifier. Defaults to M3.1-Flash-Preview (M Plan). Use MiniMax-M3 for pay-as-you-go.",
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
    # Audit R4-H5: cap on distinct (target, action) buckets so a
    # long-running process doesn't grow the in-memory bucket map without
    # bound. LRU eviction kicks in once this threshold is reached.
    RATE_LIMITER_MAX_KEYS: int = Field(
        default=10_000,
        ge=100,
        le=1_000_000,
        description=(
            "Max distinct (target, action) pairs tracked in the "
            "RateLimiter's bucket dict. LRU eviction when reached."
        ),
    )

    # ---- Concurrency control ----
    # Hard cap on how many recon modules (or jobs) can be active
    # concurrently per process. Bounded so a job selecting all 14
    # modules cannot create 14 simultaneous httpx pools against the
    # LLM provider (audit finding R4-H2 / R4-M3).
    MAX_CONCURRENT_MODULES: int = Field(
        default=4,
        ge=1,
        le=64,
        description=(
            "Max recon modules running in parallel per job. Bounds "
            "worst-case LLM and outbound IO fan-out."
        ),
    )
    MAX_CONCURRENT_JOBS: int = Field(
        default=4,
        ge=1,
        le=64,
        description=(
            "Max background jobs running in parallel per process. Bounds "
            "global rate of LLM calls across all operators."
        ),
    )

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
    tools_only_free: bool = Field(
        default=False,
        description=(
            "When True, modules with requires_paid=True are excluded from "
            "MODULE_REGISTRY at startup. Invalid string values fall back "
            "to False (fail-open: allow all modules). Env var: TOOLS_ONLY_FREE."
        ),
    )

    # ---- Rules-of-Engagement enforcement (PR 1, default off) ----
    # When true, `RoEMiddleware` gates POST /api/v1/jobs on the
    # existence of an ACTIVE RoE for the named target. The middleware
    # class is a no-op when this is false — backward compat for
    # deployments that have not opted in.
    #
    # The middleware reads the env var directly (`os.getenv`) at
    # construction time so the constructor stays decoupled from
    # pydantic-settings. This Settings field exists for operator
    # visibility (one canonical place to see every feature flag) and
    # to enable a future migration where the middleware reads
    # `settings.ROE_ENABLED` directly.
    ROE_ENABLED: bool = Field(
        default=False,
        description=(
            "Enable Rules-of-Engagement enforcement on POST /api/v1/jobs. "
            "When false (default), the middleware is a no-op and every "
            "request passes through. When true, requests without an "
            "active RoE for the named target are rejected with 403. "
            "Reads at app construction; flip by restarting the process."
        ),
    )
    ROE_SESSION_FACTORY: str | None = Field(
        default=None,
        description=(
            "Optional dotted path to override the session factory used "
            "by RoEMiddleware. Defaults to app.database.SessionLocal."
        ),
    )

    # ---- Privacy / encryption (PR 4 — person_dossier aggregator) ----
    PERSON_DOSSIER_ENCRYPTION_KEY: str | None = Field(
        default=None,
        description=(
            "Fernet key for encrypting raw emails in identity_map. "
            "Generate with `Fernet.generate_key().decode()`. If unset, "
            "encryption is skipped and dossiers still emit without "
            "identity_map rows."
        ),
    )

    # ---- Authentication (PR-J1, sec-auth-jwt Issue #29) ----
    # Field declarations only. PR-J3 / J4 wire these into the auth
    # service; PR-J1 just makes the env-var surface explicit so the
    # deployment manifests can be authored ahead of code that reads them.
    PEPPER_SECRET: str = Field(
        default="",
        description=(
            "Server-side pepper for argon2id (PR-J1 PasswordService) "
            "and HMAC-SHA256 refresh-token hashing. MUST be at least 32 "
            "bytes; rotate via docs/auth-operations.md playbook (rotating "
            "invalidates every stored hash)."
        ),
    )
    JWT_PRIVATE_KEY_PATH: str | None = Field(
        default=None,
        description=(
            "Absolute or relative path to the RS256 private key PEM "
            "(mode 0600). Generate via openssl genpkey -algorithm RSA "
            "-pkeyopt rsa_keygen_bits:2048. PR-J1 reads only."
        ),
    )
    JWT_PUBLIC_KEY_PATH: str | None = Field(
        default=None,
        description=(
            "Absolute or relative path to the matching RS256 public key " "PEM. PR-J1 reads only."
        ),
    )
    JWT_ACCESS_TTL_SECONDS: int = Field(
        default=900,
        ge=60,
        le=3600,
        description="RS256 access token TTL. Spec §7 clamp [60, 3600].",
    )
    JWT_REFRESH_TTL_SECONDS: int = Field(
        default=604_800,  # 7 days
        ge=3600,
        le=2_592_000,  # 30 days
        description="Opaque refresh token TTL. Spec §7 clamp [3600, 2592000].",
    )
    REFRESH_HASH_KEY: str = Field(
        default="",
        description=(
            "HMAC-SHA256 key used to hash refresh tokens at rest (PR-J2). "
            "MUST be at least 32 bytes. Never logged; never persisted in DB."
        ),
    )
    JWT_ISSUER: str = Field(
        default="recon-auth",
        description="``iss`` claim. PR-J3 JwtKeyManager reads this.",
    )
    ALLOW_LEGACY_API_KEY: bool = Field(
        default=True,
        description=(
            "When False, the dual-auth window is closed and RECON_API_KEY "
            "no longer authenticates anyone. Default True for the "
            "v0.1→v0.2 transition; set False at v0.3.0 (PR-J8)."
        ),
    )

    @field_validator("CORS_ORIGINS")
    @classmethod
    def _validate_cors(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("CORS_ORIGINS cannot be empty")
        return v.strip()

    @field_validator("tools_only_free", mode="before")
    @classmethod
    def _validate_tools_only_free(cls, v: object) -> bool:
        """Coerce ``TOOLS_ONLY_FREE`` env value to bool, fail-open on garbage.

        Accepted truthy: ``true``, ``1``, ``yes``, ``on`` (case-insensitive).
        Accepted falsy: ``false``, ``0``, ``no``, ``off``, ``""`` (case-insensitive).
        Anything else falls back to ``False`` (fail-open: keep all modules in
        the registry). This avoids Pydantic raising ValidationError at
        startup, which would block legitimate jobs.
        """
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        s = str(v).strip().lower()
        if s in {"true", "1", "yes", "on"}:
            return True
        if s in {"false", "0", "no", "off", ""}:
            return False
        # Fail-open: garbage value → False (allow all modules)
        return False

    @field_validator("PERSON_DOSSIER_ENCRYPTION_KEY")
    @classmethod
    def _validate_encryption_key(cls, v: str | None, info: Any) -> str | None:
        """Fail-loud when the encryption key is missing in production.

        Audit finding R1-M1 / R4-M2: ``person_dossier._store_identity_map``
        silently caught ``EncryptionKeyMissingError`` and continued
        without writing the encrypted backup row. In ``APP_ENV=production``
        this made the "encrypted at rest" contract invisibly broken and
        the handoff look complete when PII persistence was actually
        absent. Raise at boot so a misconfigured production deployment
        cannot start.

        In dev/staging/test the operator often has no key — we let it
        pass and let the runtime consumer log per-affected-hash, same
        behavior as before the hardening.
        """
        env = info.data.get("APP_ENV", "development")
        if env == "production" and not v:
            raise ValueError(
                "PERSON_DOSSIER_ENCRYPTION_KEY must be set in production. "
                "Generate one with:\n"
                '  python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        return v

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
    return Settings()
