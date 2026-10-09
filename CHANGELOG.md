# Changelog

All notable changes to zimlama/recon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (hardening bundle for v0.2.1)

This release closes the audit follow-ups from the v0.2.0 final pass (R1/R2/R4)
plus the test-reliability flakes that escaped the v0.2.0 cut. No new features —
chore-only. Tracked in PR `chore/v0.2.1-hardening-bundle`.

- **Fixed `test_paid_module_excluded_logs_warning` flake** — root cause was
  `alembic/env.py:28` calling `logging.config.fileConfig()` with the default
  `disable_existing_loggers=True`, which silently disabled every logger not
  listed in `alembic.ini` (including `app.modules`). Once the first
  `test_alembic_identity_map` test ran, every subsequent test's `caplog` could
  not capture `app.modules` warnings. Pass `disable_existing_loggers=False`.
- **Hardened `test_modules_stub` global patch** — refactored the
  `asyncio.create_subprocess_exec` direct-attribute assignment to use
  `monkeypatch.setattr`, guaranteeing restoration on teardown even if the
  process is interrupted mid-test (no more `TypeError: ... used in 'await'`
  leaks into later tests).
- **Refactored PersonDossier typing** — replaced `str` + hand-rolled
  `@field_validator` with `Literal["HIGH", "MEDIUM", "LOW"]` /
  `Literal["HIGH", "MEDIUM", "LOW", "NONE"]` to match the handoff schema and
  collapse the duplicated magic-string sets into a single source of truth
  (`_COHERENCE_LEVELS` / `_PRIORITY_LEVELS` frozensets).
- **Split `_collect_orphan_breaches_and_attach`** — 62-line helper decomposed
  into `_index_email_domains` + `_classify_breaches`; the orchestrator is
  now a 5-line delegator.
- **Removed dead `InvalidToken` re-export** from `app/utils/encryption.py`
  (no caller imported it).
- **Tightened `_assess_coherence` return type** to `CoherenceTag | None`
  with a `typing.cast` at the single return point so `mypy --strict` accepts
  the runtime narrowing via `COHERENCE_LEVELS` membership.

### Test results

- **582 tests passing** (was 581 in v0.2.0; the flake now passes deterministically)
- 0 failures, 0 known flakes
- Coverage: 91.66% on critical modules (modules + orchestrator + middleware + handoff + utils) — gate ≥ 90%
- `mypy --strict`: no new errors (pre-existing 1 unrelated `union-attr` remains)
- `ruff check`: no new errors (7 pre-existing in `person_dossier.py` unrelated to this bundle)

### CI hygiene (already in place from prior PRs, documented here for traceability)

- All GitHub Actions references are SHA-pinned with tag comments
  (`actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`, etc.)
- `dependabot.yml` covers pip + npm + github-actions + docker, weekly
- `CODEOWNERS` auto-assigns `@zimlama` for backend, frontend, CI, docs
- All workflows declare a `permissions:` block with the minimum scope
  (CI: `contents: read`; CodeQL: + `security-events: write`; release: + `contents: write` + `packages: write`)

### Compliance

- 0 `Co-Authored-By` in all 6 new commits
- 0 DragonJar / JAIME / RESTREPO references in code, docs, or tests
- All commits follow Conventional Commits format
- Apache-2.0 license header on every new/modified Python file

## [0.2.0] - 2026-10-13

### Sprint recap (v0.2.0)

PR 1-3 of the 4-PR plan implemented (PR 3 = harness layer deferred). Two fix passes closed all regressions.

- **PR 1 — Rules of Engagement (RoE) model + middleware**
- **PR 2 — touch_classification + tools_only_free filter**
- **PR 4 — person_dossier aggregator** (Tier 3, gated, privacy-by-design)
- **Audit fix pass** — closed 24/24 findings (3 CRITICAL, 9 HIGH, 7 MEDIUM, 5 LOW)
- **Test fix pass** — 11 regressions (test_modules_stub pollution) + 3 pre-existing failures (LLM kwarg, validation strings, consent validation)

### Added

- **PR 1: RoE model + middleware + validator + migration** (6 new files, 5 commits)
  - `RoE` + `SignOff` SQLAlchemy models with `RoEStatus` + `ScopeType` enums
  - `RoEValidator.is_authorized()` with `get_active_roes()` for batch queries
  - `RoEMiddleware` in `backend/app/middleware/roe.py` (env-disabled by default via `ROE_ENABLED`)
  - `backend/app/main.py:140-141` wires RoEMiddleware into `create_app()` when `ROE_ENABLED=true`
  - `Settings.ROE_ENABLED` (default False) + `ROE_SESSION_FACTORY` (optional, defaults to `SessionLocal`)
  - Alembic migration `20261007224728_add_roe_tables.py` (reversible via `alembic downgrade -1 && alembic upgrade head`)
  - 39 RoE tests (5 model + 10 validator + 14 middleware + 10 wiring/integration)

- **PR 2: touch_classification + tools_only_free filter** (5 commits)
  - `TouchClass` enum: PASSIVE_TARGET, PASSIVE_THIRDPARTY, ACTIVE_TARGET, ACTIVE_THIRDPARTY
  - `BaseReconModule.touch_classification: TouchClass` + `requires_paid: bool` (defaults free, safe)
  - All 14 modules classified per spec REQ-029 mapping table (source-verified)
  - `Settings.tools_only_free: bool` (default False)
  - `MODULE_REGISTRY` filter excluding `requires_paid=True` modules with WARNING log when enabled
  - 29 parametrized tests (mapping table + filter behavior + invalid value handling)

- **PR 4: person_dossier aggregator** (6 commits)
  - `FindingType.DOSSIER` enum value
  - `IdentityMap` SQLAlchemy model (encrypted email storage with Fernet)
  - `PersonDossier` Pydantic schema with `extra="forbid"`
  - `PersonDossierModule` (Tier 3, gated, runs after `employee_osint` + `socmint` + `breach_data`)
  - Cross-module correlation: groups findings by `email_hash` (SHA-256), aggregates confidence (+0.1 boost per multi-source corroboration, capped 1.0)
  - AI coherence assessment via MiniMax-M3 (bounded: ≤256 tokens, 30s timeout, max 1 call per dossier)
  - `backend/app/utils/encryption.py`: `hash_email()` (SHA-256) + `encrypt_email()`/`decrypt_email()` (Fernet AES-128-CBC + HMAC-SHA256)
  - Handoff schema updated: `person_dossiers: list[HandoffPersonDossierSummary]` (additive, non-breaking)
  - 101 new tests (28 model + 63 module + 10 handoff-integration)

### Changed

- `backend/app/main.py:140-141` — wires `RoEMiddleware` between CORS and audit middleware when `ROE_ENABLED=true`
- `backend/app/config.py:95,116` — added `tools_only_free: bool` + `ROE_ENABLED: bool` + `ROE_SESSION_FACTORY: str | None` Settings
- `backend/app/middleware/roe.py` + `backend/app/orchestrator/roe.py` + `backend/app/modules/person_dossier.py` — new production code
- 14 modules updated: `whois_rdap` PASSIVE_TARGET, `dns_enum` ACTIVE_TARGET, `subdomain_enum`/`certificate_transparency`/`wayback_machine`/`email_harvesting`/`shodan_censys`/`github_recon`/`metadata_analysis`/`google_dorking`/`breach_data`/`socmint`/`employee_osint`/`dark_web_osint` PASSIVE_THIRDPARTY
- `LLMClient.__init__` now accepts `max_retries: int = 3` kwarg
- Job creation endpoint rejects `user_consent=False` with HTTP 400 (LATAM-aware consent enforcement)

### Security

- Privacy-by-design (L3 verified): raw emails NEVER in logs, handoff exports, or AI prompts — SHA-256 hashing at module boundary, Fernet at rest
- SSRF defense: all external HTTP uses `BaseReconModule.safe_http_get` (follow_redirects=False, swallows `httpx.HTTPError`, returns None on failure)
- API auth: `RECON_API_KEY` env-var-gated (env-disabled by default for backward compat)
- RoE enforcement: middleware loads only when `ROE_ENABLED=true` (fail-open on startup, fail-closed on violations when enabled)
- CORS strict: only `localhost:5173,8080` (no wildcard)
- `tools_only_free` filter prevents accidental paid-module invocation
- Privacy invariants verified at 3 layers (schema / code / storage)

### Test results

- **581 tests passing** (was 421 in v0.1.0)
- 1 known flake: `test_paid_module_excluded_logs_warning` — passes in isolation, fails in full-suite due to `monkeypatch` + `caplog` ordering interaction. Pre-existing, not a regression. Tracked for v0.2.1 hardening bundle.
- Coverage: 91.64% on critical modules (modules + orchestrator + middleware + handoff + utils)

### Compliance

- 0 `Co-Authored-By` in all 37 commits
- Apache-2.0 license header on every Python file (8/8 new files)
- 0 DragonJar / JAIME / RESTREPO references in code, docs, or tests
- All commits follow Conventional Commits format
- Privacy invariants verified: 4 dedicated tests (`test_run_no_plaintext_in_logs`, `test_run_finding_metadata_has_no_plaintext_email`, `test_handoff_person_dossier_summary_rejects_plaintext_email`, `test_identity_map_stores_ciphertext_not_plaintext`)

### Known follow-ups (v0.2.1+)

- Per-module SSRF adoption (remaining modules)
- GitHub Actions SHA pinning (currently using tag refs)
- Observability: metrics, structured logs, Sentry integration
- TLS via Caddy / Cloudflare Tunnel
- Multi-user auth (JWT) for production
