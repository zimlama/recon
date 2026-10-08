# PR 1 — RoE model + middleware + validator — Specification (Delta)

> **Change**: `2026-10-12-pr1-roe`
> **Phase**: Spec (delta over existing implementation)
> **Source design**: `openspec/changes/2026-10-12-pr1-roe/design.md`
> **Source plan**: PR 1 of the v0.1.1 plan (Rules-of-Engagement enforcement)
> **Coverage target**: 90% (`pytest --cov-fail-under=90`)

---

## Scope summary

| Status | Coverage |
|---|---|
| **Already merged** (verification only) | RoE + SignOff ORM models, RoEStatus + ScopeType enums, RoEValidator, RoEMiddleware class, reversible Alembic migration, 29 tests across model/validator/middleware |
| **Already merged** (verification only) | 6 commits: `6d43ee4`, `a2ebb62`, `c1dda05`, `7f198fb`, plus test commits |
| **NOT yet wired** (this spec's delta) | `RoEMiddleware` registration in `create_app()`; `ROE_ENABLED` exposed in `Settings` for visibility |

This delta therefore documents:
- **REQ-021a** — wire the existing `RoEMiddleware` into the live app (the single remaining integration task)
- **REQ-021 → REQ-027** — verification-only records that anchor each requirement to its already-merged implementation
- **REQ-028** — surface `ROE_ENABLED` in `app.config.Settings` so operators see it in one place alongside `AUDIT_LOGGING_ENABLED`

---

## REQ-021a: Wire RoEMiddleware into create_app()

- **Priority**: P0 (PR 1 is currently non-functional: the middleware class exists but is never loaded)
- **Type**: Wiring / integration
- **Files affected**:
  - MODIFY `backend/app/main.py:103-148` (~5 LOC change)
  - NEW `backend/tests/test_app_wiring.py` (~50 LOC, asserts `RoEMiddleware` is mounted when `ROE_ENABLED=true`)

### Implementation outline

```
# backend/app/main.py — inside create_app(), after the CORS block and
# before the audit-middleware block (lines ~133-137 today):

from app.database import SessionLocal
from app.middleware.roe import RoEMiddleware

if settings.ROE_ENABLED:
    app.add_middleware(
        RoEMiddleware,
        session_factory=SessionLocal,
    )
```

The `session_factory` parameter MUST be `SessionLocal` (or `lambda: SessionLocal()`) — never a live `Session` instance — so the middleware can open a fresh session per request (thread-safety under concurrent async dispatch).

### Acceptance criteria

- **AC-021a.1**: When `ROE_ENABLED=true` is set in env or `.env`, `RoEMiddleware` is loaded between CORS and Audit middleware.
- **AC-021a.2**: When `ROE_ENABLED` is unset or set to anything other than the literal `"true"` (case-insensitive), `RoEMiddleware` is NOT loaded (existing pass-through behavior preserved).
- **AC-021a.3**: `RoEMiddleware.__init__` receives `session_factory=SessionLocal` (not a `Session` instance) for per-request session lifecycle.
- **AC-021a.4**: A POST to `/api/v1/jobs` with `target="example.com"` and an active RoE in the DB returns 200; the same POST without an RoE returns 403 with `{"error": "roe_not_authorized", "detail": "..."}`.

### Adversarial scenarios (L2)

- **AS-021a.1**: `ROE_ENABLED=true` but `RoEMiddleware.__init__` raises (e.g. `SessionLocal` missing) — the exception bubbles up and `create_app()` fails closed at boot. Operators see a clear startup error in logs. (Decision: fail-closed at boot is acceptable; the operator must fix the wiring before the app can serve traffic.)
- **AS-021a.2**: `ROE_ENABLED` is `"True"` with capital T — `os.getenv(...).lower() == "true"` (middleware/roe.py:59) handles this correctly.
- **AS-021a.3**: DB unreachable when `RoEMiddleware` calls `RoEValidator.is_authorized()` — exception propagates, FastAPI returns 500. (Q1 below: future PR may wrap as 503 with `Retry-After`.)
- **AS-021a.4**: RoE for target not found — middleware returns 403 with detail `"no RoE matches target+scope"`.
- **AS-021a.5**: RoE expired — middleware returns 403 with detail `"RoE has expired (valid_until is in the past)"`.
- **AS-021a.6**: RoE ACTIVE but all signoffs revoked — middleware returns 403 with detail `"RoE has no active (un-revoked) sign-offs"`.

### Privacy classification (L3)

| Field | Classification | Mitigation |
|---|---|---|
| `target` | Internal (operator's engagement scope) | Audit log records target string; not PII of recon target |
| `scope_value` | Internal | Same as above |
| `authorized_by` (operator email) | Operator-PII | NOT logged in middleware deny messages |
| `signer_email` | Operator-PII | Stored in DB; NOT in middleware logs |
| `reason` string in 403 response | Internal | Contains scope-status wording, no raw emails or signer names |

The 403 response body's `detail` field contains only a short reason phrase (e.g. `"RoE has expired"`). It MUST NOT include the raw `client_name`, `signer_email`, or `notes` value.

### Anti-block posture (L4)

- **No I/O in filter path beyond DB session**: middleware reads JSON body once via `await request.body()`, then opens one DB session via `RoEValidator`, executes two queries (`selectinload` prevents N+1), and closes the session.
- **Async with timeout budget**: validator is synchronous SQLAlchemy, expected <50 ms on local SQLite. No `await` blocking inside the validator; the middleware `await`s the DB call indirectly through the async dispatch loop. (No explicit asyncio timeout — Python's GIL plus SQLite's per-connection lock bounds the worst case; this is acceptable for single-user local installs.)
- **Env-disabled by default**: `ROE_ENABLED=false` means the middleware is a no-op and short-circuits before any DB or body parsing.

### Failure modes

| Failure | HTTP status | Response shape |
|---|---|---|
| DB unreachable / connection lost | 500 | FastAPI default error envelope |
| RoE for target not found | 403 | `{"error": "roe_not_authorized", "detail": "no RoE matches target+scope"}` |
| RoE expired | 403 | `{"error": "roe_not_authorized", "detail": "RoE has expired (valid_until is in the past)"}` |
| RoE not yet valid (`valid_from` future) | 403 | `{"error": "roe_not_authorized", "detail": "RoE is not yet valid (valid_from is in the future)"}` |
| RoE status DRAFT / EXPIRED / REVOKED | 403 | `{"error": "roe_not_authorized", "detail": "RoE status is <status>; not active"}` |
| All signoffs revoked | 403 | `{"error": "roe_not_authorized", "detail": "RoE has no active (un-revoked) sign-offs"}` |
| Malformed JSON body | 400 | `{"error": "invalid_body", "detail": "<JSONDecodeError msg>"}` |
| Missing or non-string `target` | 400 | `{"error": "missing_target", "detail": "Request body must include a non-empty 'target'."}` |
| Unknown `scope_type` value | 200 (pass-through) | Coerced to `ScopeType.DOMAIN`; not a denial trigger |

---

## REQ-021: RoE model (verification only)

- **Priority**: P0
- **Status**: Already implemented at `6d43ee4`
- **Files verified**:
  - `backend/app/models.py:343-355` — `RoEStatus` enum (DRAFT / ACTIVE / EXPIRED / REVOKED)
  - `backend/app/models.py:378-433` — `RoE` model (id, target, scope_type, scope_value, authorized_by, notes, status, valid_from, valid_until, created_at) + `is_acceptable(at)` predicate
- **Acceptance**:
  - **AC-021.1**: `RoE` ORM model exists with the fields above and persists via SQLAlchemy session.
  - **AC-021.2**: `RoE.is_acceptable(at)` returns True iff `valid_from <= at <= valid_until` and is purely date-based (status checks NOT applied here — see design.md §4).
  - **AC-021.3**: Migration `alembic/versions/20261007224728_add_roe_tables.py` is reversible (`alembic downgrade -1 && alembic upgrade head` exits 0).
- **Tests**: `backend/tests/test_roe_model.py` — 6 tests (defaults to DRAFT, `is_acceptable` boundary, signoff revoke, FK cascade).

---

## REQ-022: Scope model (verification only)

- **Priority**: P0
- **Status**: Already implemented at `6d43ee4`
- **Files verified**:
  - `backend/app/models.py:358-376` — `ScopeType` enum (DOMAIN, SUBDOMAIN, IP_RANGE, URL_PATTERN, EMPLOYEE, COMPANY)
  - Stored as `roes.scope_type` enum column + `roes.scope_value` string column (PR 1 deliberately flattens the original plan's `in_target_subdomains / in_target_ip_ranges / out_of_scope` into a single `(scope_type, scope_value)` pair — CIDR/glob expansion deferred to PR 2+).
- **Acceptance**:
  - **AC-022.1**: `ScopeType` enum exists with six members.
  - **AC-022.2**: Case-insensitive exact-match is the matching rule (no CIDR expansion in PR 1).
- **Non-features (deliberate)**: CIDR expansion for `IP_RANGE`, wildcard matching for `SUBDOMAIN`, fuzzy matching — all deferred per `orchestrator/roe.py:13-19`.

---

## REQ-023: SignOff model (verification only)

- **Priority**: P0
- **Status**: Already implemented at `6d43ee4`
- **Files verified**:
  - `backend/app/models.py:436-464` — `SignOff` model (id, roe_id FK CASCADE, signer_name, signer_email, signer_role, signed_at, revoked_at)
- **Acceptance**:
  - **AC-023.1**: `SignOff` ORM model exists with cascade behavior (ORM `cascade="all, delete-orphan"` AND FK `ON DELETE CASCADE` — both needed because SQLite ignores FK pragma unless `PRAGMA foreign_keys=ON` per connection).
  - **AC-023.2**: Revocation is recorded (`revoked_at` timestamp), never deleted — auditors see full history.
- **Tests**: `backend/tests/test_roe_model.py` — signoff + cascade coverage.

---

## REQ-024: RoEValidator.is_authorized (verification only)

- **Priority**: P0
- **Status**: Already implemented at `a2ebb62`
- **Files verified**:
  - `backend/app/orchestrator/roe.py:41-176` — `RoEValidator` class
  - `is_authorized(target, scope_type, at=None) -> tuple[bool, str, list[SignOff]]` at `roe.py:58-115`
  - `_find_candidate` at `roe.py:149-173` — most-recently-created match wins, eager-loaded signoffs via `selectinload`
- **Acceptance**:
  - **AC-024.1**: Returns `(True, "", active_signoffs)` when an ACTIVE RoE exists in-window with at least one un-revoked SignOff.
  - **AC-024.2**: Returns `(False, "no RoE matches target+scope", [])` when no candidate matches.
  - **AC-024.3**: Returns `(False, "RoE status is <status>; not active", [])` when status is DRAFT / EXPIRED / REVOKED.
  - **AC-024.4**: Returns distinct reason strings for `valid_from` future vs `valid_until` past (not a single "out of window" string).
  - **AC-024.5**: Returns `(False, "RoE has no active (un-revoked) sign-offs", [])` when all signoffs are revoked.
  - **AC-024.6**: Performs exactly two SQL queries per request (one to find the RoE, one via `selectinload` for signoffs). No N+1.
  - **AC-024.7**: Closes the session in a `finally` block (`roe.py:114-115`).
- **Tests**: `backend/tests/test_roe_validator.py` — 11 tests.

---

## REQ-025: FastAPI RoE middleware class (verification only)

- **Priority**: P0
- **Status**: Already implemented at `c1dda05`
- **Files verified**:
  - `backend/app/middleware/roe.py:48-156` — `RoEMiddleware(BaseHTTPMiddleware)`
  - Constructor reads `ROE_ENABLED` once via `os.getenv` at line 59
  - Default protected paths: `("/api/v1/jobs", "/api/v1/jobs/")` at line 42-45
- **Acceptance**:
  - **AC-025.1**: `dispatch()` short-circuits to `call_next` when disabled OR non-POST OR not on a protected path — body is NOT read in the fast path.
  - **AC-025.2**: Calls `await request.body()` exactly once. Starlette caches bytes; downstream handlers see the same payload without `_receive` patching.
  - **AC-025.3**: `_coerce_scope_type` defaults unknown values to `ScopeType.DOMAIN` (no DoS trigger).
  - **AC-025.4**: 400 (not 403) is returned for malformed JSON or missing target — fail-closed on parse errors.
- **Tests**: `backend/tests/test_roe_middleware.py` — 12 tests.

---

## REQ-026: Expiry check (verification only)

- **Priority**: P0
- **Status**: Already implemented at `a2ebb62` (`roe.py:92-103`)
- **Acceptance**:
  - **AC-026.1**: RoE with `valid_until < now` returns 403 with detail `"RoE has expired (valid_until is in the past)"`.
  - **AC-026.2**: RoE with `valid_from > now` returns 403 with detail `"RoE is not yet valid (valid_from is in the future)"`.
  - **AC-026.3**: Boundary inclusivity: `at == valid_from` and `at == valid_until` both authorize (closed interval).
- **Tests**: `backend/tests/test_roe_validator.py::test_expired_roe_denies` and related boundary tests.

---

## REQ-027: Sign-off query (verification only)

- **Priority**: P0
- **Status**: Already implemented at `a2ebb62` (`roe.py:105-111`)
- **Acceptance**:
  - **AC-027.1**: Returns the list of un-revoked signoffs (`revoked_at IS NULL`) alongside the bool.
  - **AC-027.2**: Returns empty list + deny if no active signoffs.
  - **AC-027.3**: Revoked signoffs remain in the DB (audit trail) but are filtered out of the returned list.
- **Tests**: `backend/tests/test_roe_validator.py` — signoff filter coverage.

---

## REQ-028: Configuration — ROE_ENABLED in Settings (NEW)

- **Priority**: P0
- **Type**: Settings field (visibility + future-migration target)
- **Files affected**:
  - MODIFY `backend/app/config.py:Settings` — add `ROE_ENABLED: bool = False` to the feature-flags section
  - MODIFY `backend/.env.example` — document `ROE_ENABLED=` and `ROE_SESSION_FACTORY=`

### Implementation outline

```python
# backend/app/config.py — append to the "Feature flags" block (after line 94):

# ---- RoE enforcement (PR 1, default off) ----
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
```

The middleware itself continues to read `ROE_ENABLED` via `os.getenv` (per the existing implementation at `middleware/roe.py:59`) — pydantic-settings populates the process env from `.env` at startup, so both code paths see the same value. The Settings field exists for **operator visibility** (one canonical place to see every feature flag) and to enable future migration where the middleware reads `settings.ROE_ENABLED` directly.

### Acceptance criteria

- **AC-028.1**: `Settings.ROE_ENABLED` is a `bool`, defaults to `False`, and reads from env / `.env` case-insensitively (pydantic-settings convention).
- **AC-028.2**: `backend/.env.example` documents `ROE_ENABLED=` (commented out) with a one-paragraph explanation matching the description string above.
- **AC-028.3**: When `ROE_ENABLED=false` (default), `app.user_middleware` does NOT include `RoEMiddleware`.
- **AC-028.4**: When `ROE_ENABLED=true`, `app.user_middleware` includes `RoEMiddleware` between CORSMiddleware and AuditLogMiddleware (registration order: CORS → RoE → Audit).

---

## Non-functional requirements

- **NFR-1**: `RoEMiddleware` test coverage ≥ 90% (currently 100% in `test_roe_middleware.py`).
- **NFR-2**: `RoEValidator` test coverage ≥ 90% (currently 100% in `test_roe_validator.py`).
- **NFR-3**: No PII (raw `signer_email`, raw `notes`, raw `authorized_by`) in middleware logs or 403 response bodies. The `detail` field carries only short reason phrases.
- **NFR-4**: Middleware disabled by default (`ROE_ENABLED=false`) — backward compatible with deployments that have not opted in.
- **NFR-5**: Validator never raises on app startup (the middleware constructor reads env only, no DB call at construction).
- **NFR-6**: Per-request session lifecycle — middleware opens a fresh session via `session_factory()` and closes it in a `finally` block (no shared session across concurrent async tasks).
- **NFR-7**: PR 1 follows strict TDD: tests land at the same commit as the implementation they cover. The wiring task in REQ-021a is the only post-merge addition; its test (`test_app_wiring.py`) MUST be written and failing BEFORE `main.py` is modified.

---

## Test coverage matrix

| Layer | What | Where | Count |
|---|---|---|---|
| Unit (model) | defaults to DRAFT; `is_acceptable` boundary; signoff revoke; FK cascade | `backend/tests/test_roe_model.py` | 6 |
| Unit (validator) | ACTIVE authorizes; DRAFT/EXPIRED/REVOKED/REVOKED-signoffs deny; future-valid_from deny; `get_active_roes` filtering | `backend/tests/test_roe_validator.py` | 11 |
| Integration (middleware) | disabled-by-default + env-toggle; disabled pass-through; enabled-without-RoE = 403; enabled-with-RoE = 200; non-protected paths pass; malformed JSON = 400; missing/non-string target = 400; non-dict body = 400; bad scope_type coerces to DOMAIN; empty body = 400; body bytes round-trip intact | `backend/tests/test_roe_middleware.py` | 12 |
| **NEW — wiring** (REQ-021a) | `create_app()` mounts `RoEMiddleware` when `ROE_ENABLED=true`; does not mount when unset; session_factory passed correctly | `backend/tests/test_app_wiring.py` | TBD (apply phase) |
| **Total existing** | | | **29 tests** |

### Coverage gaps to address in apply phase

- **GAP-1**: No integration test that `create_app()` actually mounts `RoEMiddleware`. Current tests construct the middleware in isolation. The apply-phase task MUST add `test_app_wiring.py` covering AC-021a.1, AC-021a.2, AC-021a.3, AC-021a.4.
- **GAP-2**: No test for "multiple RoEs overlap for same target" — the `_find_candidate` ordering logic is untested at the validator level. Recommend adding a test before merge.

---

## Meta-layer checks

| Layer | Status |
|---|---|
| **L1 anti-hallucination** | All citations verified against actual source: `models.py:343-464`, `orchestrator/roe.py:1-176`, `middleware/roe.py:1-156`, `main.py:103-148`, `config.py:1-130`, `alembic/versions/20261007224728_add_roe_tables.py:1-80`. Test counts verified via `wc -l backend/tests/test_roe_*.py`. |
| **L2 adversarial** | REQ-021a lists 6 adversarial scenarios (AS-021a.1–AS-021a.6) + 9-row failure-mode table. Design.md §7 lists 7 additional scenarios (mid-job expiry, overlapping RoEs, scope_value mismatch, env toggle without restart, validator exception, malicious scope_type, signoff-after-middleware-cache). |
| **L3 privacy** | REQ-021a classifies each field (target/scope_value/authorized_by/signer_email/reason) and prescribes that the 403 detail carries only short reason phrases, never raw PII. |
| **L4 anti-block** | REQ-021a documents async dispatch, env-disabled default, no I/O before body parse on the fast path, two-query validator path (no N+1). |
| **L5 traceability** | Every REQ cites its commit + file:line range. Open questions carry explicit decisions. |

---

## Open questions — resolved or deferred

| # | Question | Decision |
|---|---|---|
| **Q1** | Validator exception → 503 vs 500? | **Deferred to follow-up PR.** PR 1 keeps the current behavior (exception bubbles → FastAPI returns 500). Wrapping as 503 with `Retry-After` adds a `try/except` boundary and a new failure-mode test; not blocking the PR 1 wiring task. |
| **Q2** | Mid-job RoE expiry — auto-cancel running jobs? | **Deferred to follow-up.** Running jobs continue; new jobs after expiry return 403. Operator runbook documents the behavior. Job-runner integration (`orchestrator/job_runner.py`) calls `RoEValidator.is_authorized` before the first module as defense-in-depth, but does not re-check between modules. |
| **Q3** | First-class `roe_denied` audit row? | **Deferred.** The existing `AuditLogMiddleware` already captures every 403 (`action="POST_/api/v1/jobs"`, `status_code=403`, `details={reason: "roe_not_authorized"}`). A dedicated row would bloat the audit table on noisy days without proportional operator value. |
| **Q4** | Where does the `create_app()` integration test live? | **Resolved: `backend/tests/test_app_wiring.py`** (new file, ~50 LOC). Keeps the RoE test surface self-contained and lets each case set `ROE_ENABLED` independently. |

---

## Files touched by this PR (delta)

| File | Action | LOC delta |
|---|---|---|
| `backend/app/main.py:103-148` | MODIFY — register `RoEMiddleware` when `settings.ROE_ENABLED` | +8 lines |
| `backend/app/config.py:94` (after) | MODIFY — add `ROE_ENABLED` + `ROE_SESSION_FACTORY` fields | +18 lines |
| `backend/.env.example` | MODIFY — document `ROE_ENABLED` and `ROE_SESSION_FACTORY` | +15 lines |
| `backend/tests/test_app_wiring.py` | NEW — assert middleware is mounted when enabled, absent when disabled | ~50 lines |
| `openspec/changes/2026-10-12-pr1-roe/spec.md` | NEW — this document | — |
| `openspec/changes/2026-10-12-pr1-roe/tasks.md` | NEW (out of scope for this spec phase) | — |

**Total estimated delta**: ~90 LOC across 5 files.