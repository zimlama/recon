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

    # ---- Inbound rate limiting (PR-J3.6 — sec-auth-jwt follow-up) ----
    # 7 route templates per spec REQ-INB-006, locked by proposal.md
    # decision O (post-gate correction). Each tuple is
    # ``(requests_limit, window_seconds)``. Keys are route TEMPLATES
    # (with ``{job_id}`` and ``{module_name}`` placeholders preserved);
    # the middleware compiles a regex per entry against
    # ``request.url.path`` at app startup (spec REQ-INB-016 — using
    # ``request.scope["route"].path`` would fail-open because that
    # field is ``None`` inside ``BaseHTTPMiddleware.dispatch``).
    RATE_LIMITS: dict[str, tuple[int, int]] = Field(
        default_factory=lambda: {
            "/api/v1/auth/login": (10, 60),
            "/api/v1/auth/refresh": (60, 60),
            "/api/v1/jobs": (10, 60),
            "/api/v1/jobs/{job_id}/cancel": (30, 60),
            "/api/v1/ai/jobs/{job_id}/validate": (10, 60),
            "/api/v1/ai/jobs/{job_id}/modules/{module_name}/validate": (10, 60),
            "/api/v1/jobs/{job_id}/report": (5, 60),
        },
        description=(
            "Per-endpoint inbound rate-limit policy: route template → "
            "(requests_limit, window_seconds). Endpoints not in this "
            "dict are FAIL-OPEN (no policy applied) per spec REQ-INB-016. "
            "Compilied at app startup into regexes against "
            "``request.url.path``."
        ),
    )
    ALLOW_DEV_BYPASS: bool = Field(
        default=False,
        description=(
            "Enable the X-Bypass-Rate-Limit header for ops/loadtest "
            "use. Validator forces False when APP_ENV=='production' "
            "regardless of env var value (spec REQ-INB-010, gated to "
            "match the PR #56 B2 dev-mode admin bypass pattern)."
        ),
    )
    RATE_LIMIT_BYPASS_TOKEN: str = Field(
        default="",
        description=(
            "Static token the client must send in the X-Bypass-Rate-Limit "
            "header to skip the rate-limit check. REQUIRED (non-empty) "
            "when ALLOW_DEV_BYPASS=True; validator enforces that. Empty "
            "in production."
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

    @field_validator("PEPPER_SECRET")
    @classmethod
    def _validate_pepper_secret(cls, v: str, info: Any) -> str:
        """Fail-loud when ``PEPPER_SECRET`` is missing or weak in production.

        R1 Risk review (PR-J1 B-2): the PasswordService reads
        ``PEPPER_SECRET`` via ``os.environ.get(..., "")``. Without this
        validator, an empty pepper boots happily, the deployment manifest
        publishes empty, and a stolen DB can be brute-forced at full
        argon2 speed (no second secret to crack).

        Operator-friendly rule (matches PERSON_DOSSIER_ENCRYPTION_KEY):
        empty / short values are accepted in development/staging/test so
        unit tests and local operators can boot without ceremony; the
        fail-loud gate fires only in ``APP_ENV=production``.
        """
        env = info.data.get("APP_ENV", "development")
        if env == "production":
            if v == "":
                raise ValueError(
                    "PEPPER_SECRET must be set in production. "
                    "Generate one with: openssl rand -base64 32"
                )
            if len(v) < 32:
                raise ValueError(
                    f"PEPPER_SECRET must be at least 32 bytes when set; " f"got {len(v)} bytes"
                )
        elif v != "" and len(v) < 32:
            # Dev/staging/test: validate length when an operator does
            # set a value, so a typo like ``PEPPER_SECRET=x`` doesn't
            # silently weaken the production-style deployment that
            # promotes with APP_ENV unchanged.
            raise ValueError(
                f"PEPPER_SECRET must be at least 32 bytes when set; " f"got {len(v)} bytes"
            )
        return v

    @field_validator("REFRESH_HASH_KEY")
    @classmethod
    def _validate_refresh_hash_key(cls, v: str, info: Any) -> str:
        """Fail-loud when ``REFRESH_HASH_KEY`` is missing or weak in production.

        Refresh-token hashes are stored at rest (PR-J2). If the HMAC
        key is empty, the storage falls back to an unsalted SHA-256,
        which is publicly brute-forceable for 256-bit-entropy tokens.
        A leaked DB then leaks live refresh tokens.

        Same leniency rules as ``PEPPER_SECRET``.
        """
        env = info.data.get("APP_ENV", "development")
        if env == "production":
            if v == "":
                raise ValueError(
                    "REFRESH_HASH_KEY must be set in production. "
                    "Generate one with: openssl rand -base64 32"
                )
            if len(v) < 32:
                raise ValueError(
                    f"REFRESH_HASH_KEY must be at least 32 bytes when set; " f"got {len(v)} bytes"
                )
        elif v != "" and len(v) < 32:
            raise ValueError(
                f"REFRESH_HASH_KEY must be at least 32 bytes when set; " f"got {len(v)} bytes"
            )
        return v

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

    @field_validator("RATE_LIMITS", mode="before")
    @classmethod
    def _validate_rate_limits(cls, v: object) -> dict[str, tuple[int, int]]:
        """Validate the per-endpoint rate-limit table (spec REQ-INB-006).

        Each entry MUST be a 2-tuple of ``(requests_limit, window_seconds)``.
        ``requests_limit`` must be an int in ``[1, 1_000_000]``;
        ``window_seconds`` must be a positive int. Default in
        ``field.default_factory`` provides the 7-entry baseline; this
        validator runs BEFORE that factory on env-driven loads.
        """
        if v is None:
            return v  # type: ignore[return-value]
        if not isinstance(v, dict):
            raise ValueError(
                f"RATE_LIMITS must be a dict[str, tuple[int, int]], "
                f"got {type(v).__name__}"
            )
        out: dict[str, tuple[int, int]] = {}
        for key, raw in v.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"RATE_LIMITS keys must be str route templates, "
                    f"got {type(key).__name__}: {key!r}"
                )
            # pydantic-settings serializes tuples as JSON arrays on
            # env-driven loads — so accept either tuple or list of
            # length 2 with int entries.
            seq = raw if isinstance(raw, (tuple, list)) else None
            if seq is None or len(seq) != 2:
                raise ValueError(
                    f"RATE_LIMITS[{key!r}] must be (requests_limit, "
                    f"window_seconds); got {raw!r}"
                )
            requests, window = seq[0], seq[1]
            try:
                requests_i = int(requests)
                window_i = int(window)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"RATE_LIMITS[{key!r}] values must be ints; "
                    f"got {raw!r}"
                ) from exc
            if requests_i < 1 or requests_i > 1_000_000:
                raise ValueError(
                    f"RATE_LIMITS[{key!r}] requests_limit must be in "
                    f"[1, 1_000_000], got {requests_i}"
                )
            if window_i < 1:
                raise ValueError(
                    f"RATE_LIMITS[{key!r}] window_seconds must be a "
                    f"positive int, got {window_i}"
                )
            out[key] = (requests_i, window_i)
        return out

    @field_validator("ALLOW_DEV_BYPASS", mode="before")
    @classmethod
    def _validate_allow_dev_bypass(cls, v: object, info: Any) -> bool:
        """Coerce + gate ``ALLOW_DEV_BYPASS`` (spec REQ-INB-010).

        Accepts the usual truthy strings (``true``, ``1``, ``yes``,
        ``on``). Force-disables to ``False`` when ``APP_ENV=='production'``
        regardless of env value — same dev-only pattern as the PR #56 B2
        admin-bypass fix. Acts BEFORE ``info`` so we still see the
        string on env loads.
        """
        if isinstance(v, bool):
            coerced = v
        elif v is None:
            coerced = False
        else:
            s = str(v).strip().lower()
            coerced = s in {"true", "1", "yes", "on"}
        env = info.data.get("APP_ENV", "development")
        if env == "production" and coerced:
            return False
        return coerced

    @field_validator("RATE_LIMIT_BYPASS_TOKEN")
    @classmethod
    def _validate_bypass_token(cls, v: str, info: Any) -> str:
        """Require non-empty bypass token whenever the feature is enabled.

        Spec REQ-INB-010: "RATE_LIMIT_BYPASS_TOKEN MUST be required
        (non-empty) when ALLOW_DEV_BYPASS is True." Reading the
        already-validated ``ALLOW_DEV_BYPASS`` from ``info.data``.
        """
        allow = info.data.get("ALLOW_DEV_BYPASS", False)
        if allow and not v:
            raise ValueError(
                "RATE_LIMIT_BYPASS_TOKEN must be set (non-empty) when "
                "ALLOW_DEV_BYPASS=True. Set a static shared secret in "
                "your env or disable the bypass."
            )
        return v

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
