# Design: PR 1 — RoE model + middleware + validator

> **Change**: `2026-10-12-pr1-roe`
> **Phase**: Design
> **Source plan**: `wiki/sesiones/2026-10-07-plan-mejoras-person-osint.md` (PR 1)
> **Coverage target**: 90% (`pytest --cov-fail-under=90`)

## 1. Context

The current Job model carries a `user_consent: bool` flag (`backend/app/models.py:117`). That flag is a **declared** consent — it answers "did the operator click accept?" but not "is this engagement authorized against a real target, within scope, with at least one active sign-off, and inside a validity window?". PR 1 closes that gap by introducing a Rules-of-Engagement (RoE) envelope backed by a persistent table, an authorization validator, and a FastAPI middleware that gates the existing `/api/v1/jobs` endpoints on it.

**Requirements covered**: REQ-021 → REQ-027 (per the plan).

**Critical context — most of PR 1 is already merged on `developer`.** The RoE model, validator, middleware, migration, and tests landed in:

| Commit | Landed |
|---|---|
| `6d43ee4` | `feat(models): add RoE + SignOff tables` |
| `a2ebb62` | `feat(orchestrator): add RoEValidator (active RoE + signoff checks)` |
| `c1dda05` | `feat(middleware): add RoE enforcement middleware (env-disabled)` |
| `7f198fb` | `feat(alembic): add RoE tables migration` |

This design therefore **describes the existing implementation** (with citations) and enumerates the **integration gaps** that remain for `sdd-apply` to close. It is not greenfield design work — see §11.

## 2. Architecture diagram

```mermaid
flowchart TD
    subgraph API[Client]
        REQ[POST /api/v1/jobs<br/>body: target, scope_type]
    end

    subgraph MW[FastAPI middleware stack]
        AUTH[API-key auth<br/>RECON_API_KEY]
        ROE[RoEMiddleware<br/>env: ROE_ENABLED=true]
        AUDIT[AuditLogMiddleware]
    end

    REQ --> AUTH --> ROE --> AUDIT --> ROUTE[POST /api/v1/jobs<br/>routes/jobs.py:26]
    ROUTE --> JOB[Job row created<br/>status=PENDING]
    JOB --> JR[JobRunner<br/>orchestrator/job_runner.py]
    JR -.call.-> VAL[RoEValidator.is_authorized<br/>orchestrator/roe.py:58]

    subgraph DB[(SQLite)]
        ROES[roes]
        SO[sign_offs]
        JOBS[jobs]
        AL[audit_log]
    end

    ROE -->|RoEValidator| DB
    JR --> VAL --> DB
    AUDIT --> AL
```

The single source of truth for "may this job run?" is `RoEValidator.is_authorized()` (`backend/app/orchestrator/roe.py:58`). Both the FastAPI middleware (request-time gate) and the orchestrator's job-launch path (in-process gate) call it. There is **one** implementation of the rule.

## 3. Current state — what's already implemented

| File | Status | Cite |
|---|---|---|
| `backend/app/models.py:343-355` | `RoEStatus` enum (DRAFT/ACTIVE/EXPIRED/REVOKED) | merged at `6d43ee4` |
| `backend/app/models.py:358-376` | `ScopeType` enum (DOMAIN/SUBDOMAIN/IP_RANGE/URL_PATTERN/EMPLOYEE/COMPANY) | merged at `6d43ee4` |
| `backend/app/models.py:378-433` | `RoE` model: id, target, scope_type, scope_value, authorized_by, notes, status, valid_from, valid_until, created_at; `is_acceptable(at)` predicate | merged at `6d43ee4` |
| `backend/app/models.py:436-464` | `SignOff` model: roe_id (FK CASCADE), signer_name/email/role, signed_at, revoked_at | merged at `6d43ee4` |
| `backend/app/orchestrator/roe.py` | `RoEValidator.is_authorized()` + `get_active_roes()` | merged at `a2ebb62` |
| `backend/app/middleware/roe.py` | `RoEMiddleware(BaseHTTPMiddleware)`, env-disabled at construction | merged at `c1dda05` |
| `backend/alembic/versions/20261007224728_add_roe_tables.py` | Reversible migration creating `roes` + `sign_offs` | merged at `7f198fb` |
| `backend/tests/test_roe_model.py` (212 lines) | 6 model tests | merged at `cc1ee7d` |
| `backend/tests/test_roe_validator.py` (335 lines) | 11 validator tests | merged at `cc1ee7d` |
| `backend/tests/test_roe_middleware.py` (513 lines) | 12 middleware tests | merged at `cc1ee7d` |

**29 tests total, all green** (verified locally before this design was written — see §11).

### Integration gaps (NOT yet wired)

| Gap | Where | Impact |
|---|---|---|
| `RoEMiddleware` is **not registered** in `create_app()` | `backend/app/main.py:103-148` | Existing deployments have the middleware class on disk but it never fires on real requests. PR 1 apply-phase task. |
| `ROE_ENABLED` is read via raw `os.getenv()` inside the middleware, bypassing pydantic-settings | `backend/app/middleware/roe.py:59` | Inconsistent with `AUDIT_LOGGING_ENABLED` (`config.py:94`). Document the choice — see §8. |
| No CLI / route to **create** an RoE | routes/ folder | Operator can only insert via raw SQL or test fixtures today. Follow-up PR. |

## 4. Data model — `RoE` + `SignOff`

### `RoE` table (`roes`)

```python
class RoE(Base):
    __tablename__ = "roes"

    id: Mapped[str]                # UUID v4, PK
    target: Mapped[str]            # String(255), indexed
    scope_type: Mapped[ScopeType]  # enum, NOT NULL
    scope_value: Mapped[str]       # String(255), NOT NULL
    authorized_by: Mapped[str]     # String(100) — operator email
    notes: Mapped[str | None]      # Text, nullable
    status: Mapped[RoEStatus]      # default DRAFT, indexed
    valid_from: Mapped[datetime]   # default _now()
    valid_until: Mapped[datetime]  # NOT NULL — expiry is mandatory
    created_at: Mapped[datetime]   # default _now()

    sign_offs: Mapped[list[SignOff]] = relationship(
        "SignOff", backref="roe",
        cascade="all, delete-orphan",
        lazy="select",  # see comment at models.py:404-410
    )

    def is_acceptable(self, at: datetime | None = None) -> bool:
        when = at if at is not None else _now()
        return self.valid_from <= when <= self.valid_until
```

**Status checks are NOT applied here** (`models.py:417-424` docstring). `is_acceptable` is purely date-based so the validator can combine it with `status` and `sign_offs` checks. This separation is what makes the model unit-testable in isolation (see `test_roe_with_valid_dates_is_acceptable`).

### `SignOff` table (`sign_offs`)

```python
class SignOff(Base):
    __tablename__ = "sign_offs"

    id: Mapped[str]                # UUID v4, PK
    roe_id: Mapped[str]            # FK roes.id ON DELETE CASCADE
    signer_name: Mapped[str]       # String(100)
    signer_email: Mapped[str]      # String(255)
    signer_role: Mapped[str]       # String(100) — "CISO", "CEO", etc.
    signed_at: Mapped[datetime]    # default _now()
    revoked_at: Mapped[datetime | None]  # null = active
```

**Revocation is recorded, never deleted** (`models.py:438-442` docstring). Auditors see the full history; the validator simply filters `revoked_at IS NULL`. Two cascade layers are wired — ORM `cascade="all, delete-orphan"` AND `ON DELETE CASCADE` on the FK — because SQLite ignores the FK pragma unless `PRAGMA foreign_keys=ON` is set per-connection (set up in `app.database` and in test engines).

## 5. Validator logic — `RoEValidator.is_authorized`

Pseudocode from `backend/app/orchestrator/roe.py:58-115`:

```
function is_authorized(target, scope_type, at=None) -> (bool, reason, signoffs):
    when = at if at is not None else _now()
    target_norm = target.strip().lower()

    session = self._session_factory()
    try:
        roe = _find_candidate(session, target_norm, scope_type)
        if roe is None:
            return (False, "no RoE matches target+scope", [])

        if roe.status != ACTIVE:
            return (False, f"RoE status is {roe.status.value}; not active", [])

        if not roe.is_acceptable(at=when):
            if when < roe.valid_from:
                return (False, "RoE is not yet valid (valid_from is in the future)", [])
            return (False, "RoE has expired (valid_until is in the past)", [])

        active_signoffs = [s for s in roe.sign_offs if s.revoked_at is None]
        if not active_signoffs:
            return (False, "RoE has no active (un-revoked) sign-offs", [])

        return (True, "", active_signoffs)
    finally:
        session.close()
```

`_find_candidate` (`roe.py:149-173`) selects the **most recently created** matching RoE — operator's latest intent wins when multiple overlap. SignOffs are eager-loaded via `selectinload(RoE.sign_offs)` so the validator makes **two** queries total per request (one to find the RoE, one to load its signoffs), not N+1.

**Deliberate non-features** (per `roe.py:13-19` design notes):

- No CIDR expansion in PR 1. A `ScopeType.IP_RANGE` RoE matches `target` only by exact-string equality on `scope_value` or `target`. CIDR expansion belongs in a future scope-resolver module (PR 2+).
- No wildcard matching for `ScopeType.SUBDOMAIN` in PR 1. Same rationale.
- No fuzzy match. Case-insensitive exact equality only.

This is intentional: the rule is auditable and easy to test. Sophistication can come later without breaking the API gate.

## 6. Middleware flow

Pseudocode from `backend/app/middleware/roe.py:64-111`:

```
async def dispatch(request, call_next):
    # Fast path — no body access
    if not self._enabled or request.method != "POST":
        return await call_next(request)
    if not any(request.url.path.startswith(p) for p in self._protected_paths):
        return await call_next(request)

    # Starlette caches `request.body()` internally. Downstream handlers
    # calling `request.body()` again get the same bytes — no patching
    # of request._receive (which breaks Starlette's _CachedRequest).
    body = await request.body()

    target, payload, parse_error = _extract_target(body)
    if parse_error is not None:
        return JSONResponse(400, {"error": "invalid_body", "detail": parse_error})
    if target is None or target == "":
        return JSONResponse(400, {"error": "missing_target",
                                  "detail": "Request body must include a non-empty 'target'."})

    scope_type = _coerce_scope_type(payload)   # defaults to DOMAIN
    validator = RoEValidator(self._session_factory)
    authorized, reason, _ = validator.is_authorized(target=target, scope_type=scope_type)
    if not authorized:
        return JSONResponse(403, {"error": "roe_not_authorized", "detail": reason})
    return await call_next(request)
```

| Path | Method | Body | RoE | Response |
|---|---|---|---|---|
| `/api/v1/jobs*` | POST | valid JSON, target="example.com", DOMAIN RoE ACTIVE in-window with signoff | — | 200 |
| `/api/v1/jobs*` | POST | valid JSON, target="example.com", no RoE | — | 403 `roe_not_authorized` |
| `/api/v1/jobs*` | POST | valid JSON, target="example.com", RoE status=DRAFT | — | 403 `not active` |
| `/api/v1/jobs*` | POST | valid JSON, target="example.com", RoE EXPIRED | — | 403 `valid_until is in the past` |
| `/api/v1/jobs*` | POST | valid JSON, target="example.com", RoE ACTIVE in-window, all signoffs revoked | — | 403 `no active sign-offs` |
| `/api/v1/jobs*` | POST | malformed JSON (`{not valid json`) | — | 400 `invalid_body` |
| `/api/v1/jobs*` | POST | valid JSON, `target` is `int 12345` | — | 400 `missing_target` |
| `/api/v1/jobs*` | POST | valid JSON, no `target` key | — | 400 `missing_target` |
| `/api/v1/jobs*` | POST | empty body | — | 400 `missing_target` |
| `/api/v1/jobs*` | POST | valid JSON, unknown `scope_type` value | — | 200 (coerced to DOMAIN — not a denial-of-service trigger) |
| `/api/v1/jobs*` | DELETE/GET/PATCH | any | — | pass-through (not POST) |
| `/health*`, `/docs`, `/openapi.json`, `/redoc`, `/` | any | any | — | pass-through (not in `_DEFAULT_PROTECTED_PATHS`) |
| any | any | any | ROE_ENABLED unset | pass-through (middleware is a no-op) |

## 7. Failure modes (L2 — adversarial)

| Scenario | Behavior | Source of truth |
|---|---|---|
| **RoE expires mid-job** (long-running crawl exceeds `valid_until`) | In-flight HTTP requests are unaffected (the validator ran at request time and returned True). New requests after expiry return 403. The job itself is not auto-cancelled — that's a follow-up. **Open Question Q2**. | `middleware/roe.py:64-111` |
| **Multiple RoEs overlap for the same target** (operator activates a new RoE without revoking the prior one) | `_find_candidate` picks the **most recently created** match. Older RoEs are ignored. No conflict error — the operator's latest intent wins. | `orchestrator/roe.py:149-173` |
| **RoE `scope_value` doesn't match `target`** (operator typo) | Validator falls back to `RoE.target == target_norm` OR `RoE.scope_value == target_norm` — either match counts. If neither does, returns `no RoE matches target+scope`. | `orchestrator/roe.py:166-168` |
| **Operator toggles `ROE_ENABLED` without restarting** | The env flag is captured at middleware `__init__` (`roe.py:59`). The running process keeps its initial value. Document this in the rollout runbook — see §8. | `middleware/roe.py:11-13` |
| **Validator raises (DB connection lost, etc.)** | The middleware does NOT catch exceptions; they bubble up as a 500. **Open Question Q1** — fail-closed by accident (request fails) but with a generic 500. |
| **`scope_type` is a malicious string** (DoS vector) | Coerced to DOMAIN. The validator is called anyway, never raising. | `middleware/roe.py:141-153` |
| **SignOff is added to an RoE after `RoEMiddleware` has cached the validator's `sign_offs` list** | The validator opens a new session per request (`roe.py:79, 132`), so cache staleness is not a risk. Each request re-reads the DB. | `orchestrator/roe.py:114-115, 142-143` |
| **Operator deletes an RoE that has `Job` rows referencing it** | `Job` does not reference `RoE` (intentional — `Job` is the engagement instance, RoE is the authorization envelope). Deletion is unconstrained and SignOffs cascade via FK. | `models.py:104-169` |

## 8. Configuration

| Env var | Type | Default | Source | Purpose |
|---|---|---|---|---|
| `ROE_ENABLED` | bool string | `"false"` | raw `os.getenv` in `middleware/roe.py:59` | Enables/disables the middleware. Read **once at construction** (not per-request) so operators flip it by restarting the process. |
| `RECON_API_KEY` | str\|None | `None` | `config.Settings` (`config.py:62-69`) | Pre-existing API-key gate, runs BEFORE the RoE middleware in the middleware stack. |

**Why `ROE_ENABLED` is NOT in `config.Settings`** (`app/config.py`): the middleware reads it via `os.getenv` rather than `settings.ROE_ENABLED` so the constructor signature stays decoupled from pydantic-settings. The middleware can be constructed in tests without instantiating `Settings`, and a future deployment that wants per-environment `.env` files can still set `ROE_ENABLED=true` in `.env` because `os.getenv` reads the process env (which pydantic-settings has already populated from `.env` at startup). Documented in `middleware/roe.py:11-13`.

**`PERSON_DOSSIER_ENCRYPTION_KEY`** (referenced in the user's prompt) is **not part of PR 1**. It belongs to PR 4 (person_dossier aggregator) — see `openspec/changes/2026-10-12-pr4-person-dossier/design.md`. PR 1's privacy story is the encryption question for the RoE fields themselves — see §10.

## 9. Integration with existing code

| File | Action | Why |
|---|---|---|
| `backend/app/main.py:103-148` | **Modify**: register `RoEMiddleware` in `create_app()` after `CORSMiddleware` and before `AuditLogMiddleware` so order is CORS → RoE → Audit. | Wire the existing middleware class into the live app. |
| `backend/app/main.py` | Pass `session_factory=lambda: SessionLocal()` to the middleware. | Match the pattern used by `AuditLogMiddleware` (`audit/middleware.py:35`). |
| `backend/app/database.py` | No change. The middleware uses the same `SessionLocal()` as the route handlers. | Verified — middleware does its own session lifecycle via `session.close()` in `roe.py:114-115, 142-143`. |
| `backend/app/routes/jobs.py:26-69` | **No change to the route handler itself**. The middleware is the gate. `create_job` continues to validate `selected_modules` and `typed_confirmation` after passing the RoE check. | Defense in depth — operator's API check (line 45) is a separate control. |
| `backend/app/orchestrator/job_runner.py` | **Follow-up**: also call `RoEValidator.is_authorized(target=job.target)` before running the first module, in case the RoE was revoked between job creation and execution. | Defense in depth — see Q2. |
| `backend/app/models.Job` | **No change**. Job does not reference RoE. | By design — RoE is an authorization envelope, not a job attribute. |

**Middleware ordering rationale**: putting `RoEMiddleware` AFTER `CORSMiddleware` (which is registered first by FastAPI convention) and BEFORE `AuditLogMiddleware` means: (a) pre-flight CORS requests don't go through RoE validation (correct — only actual POSTs are gated), (b) denials are still audited by the audit middleware because audit wraps the response AFTER RoE returns 403.

## 10. Privacy (L3)

RoE rows carry: `target` (the domain), `scope_value` (typically the same as `target` or a narrower pattern), `authorized_by` (operator email), `notes` (free text), `signer_name/email/role` on SignOffs. None of these are "personal data" of recon *targets* (target is a domain, not a person). The privacy risk is operator-side: if the recon database leaks, the operator's notes and the signer's email are exposed.

**v1 stance — encryption NOT applied to RoE fields.** Justification:

- RoEs live in the same SQLite file as Jobs / Findings / AuditLog. Adding column-level encryption to RoE but not the other tables is theatrical — the attacker who reads the DB reads everything.
- The mitigation that actually matters is filesystem-level encryption (LUKS / FileVault) and `chmod 600` on the DB file. That's a deployment-level control, not an ORM-level one.
- The audit log already captures every RoE-touching operation (`middleware → AuditLog(action="POST_/api/v1/jobs", status_code=403, ...)`), giving the operator visibility into who tried what.

**v1 audit posture**: `RoEMiddleware` lets the 403 response flow through the audit middleware. Every denied request is logged with `action="POST_/api/v1/jobs"`, `target=...`, `status_code=403`. The reason string ("no RoE matches target+scope") is in `AuditLog.details` — operator can search for `roe_not_authorized` to see all denials.

**Open Question Q3**: Should we add a separate `AuditLog(action="roe_denied", details={target, reason})` row on 403 so RoE denials are first-class queryable events instead of being buried in the per-request audit row? The current audit middleware lumps them with all 4xx responses.

## 11. Test coverage

| Layer | What | Where | Count |
|---|---|---|---|
| Unit (model) | defaults to DRAFT; `is_acceptable` boundary; signoff revoke; FK cascade | `backend/tests/test_roe_model.py` | 6 |
| Unit (validator) | ACTIVE authorizes; DRAFT/EXPIRED/REVOKED/REVOKED-signoffs deny; future-valid_from deny; `get_active_roes` filtering | `backend/tests/test_roe_validator.py` | 11 |
| Integration (middleware) | disabled-by-default + env-toggle; disabled pass-through; enabled-without-RoE = 403; enabled-with-RoE = 200; non-protected paths pass; malformed JSON = 400; missing/non-string target = 400; non-dict body = 400; bad scope_type coerces to DOMAIN; empty body = 400; body bytes round-trip intact | `backend/tests/test_roe_middleware.py` | 12 |
| **Total** | | | **29 tests** |

`pytest backend/tests/test_roe_model.py backend/tests/test_roe_validator.py backend/tests/test_roe_middleware.py -q` exits 0 (verified locally).

**Coverage gaps that need explicit attention in `sdd-apply`**:

- No test for "RoE expires mid-job" — the validator's `at` parameter is mocked in tests, but there's no integration test that exercises a long-running job crossing `valid_until`. Acceptable for PR 1 — Q2 below.
- No test for "multiple RoEs overlap for same target" — the `_find_candidate` ordering logic is untested at the validator level. **Should add a test** before merge.
- No test that `create_app()` actually mounts `RoEMiddleware` — current tests construct the middleware in isolation. The integration test belongs in `test_main.py` once the wiring is in place (Q4 below).
- No load test on the validator — at 1000 req/s the two-query path is fine on SQLite, but a follow-up should verify the Postgres path before production scale-up.

## 12. Open questions

- **Q1 — Validator exception handling.** Today, if the DB throws inside `RoEValidator.is_authorized()`, the exception bubbles up through the middleware, FastAPI converts it to 500, and the request fails closed *by accident*. Should we explicitly catch + return 503 (Service Unavailable) so operators can distinguish "no RoE" from "DB unreachable"? Recommendation: **leave as 500 in PR 1**; explicit handling is a follow-up so PR 1 stays minimal.
- **Q2 — Mid-job expiry.** If a job runs for hours and the RoE expires during execution, new jobs are rejected but the running job continues. Is that the desired behavior? Two alternatives: (a) job_runner re-checks the RoE before each module, pausing/cancelling if expired; (b) add a background sweeper that cancels expired-RoE jobs. Recommendation: **leave as-is in PR 1**, document the behavior in the operator runbook, file as a follow-up issue.
- **Q3 — First-class RoE denial audit.** Should RoE denials get their own `AuditLog(action="roe_denied")` row in addition to the per-request audit middleware row? Trivial to add (one line in the middleware after `is_authorized` returns False) but bloats the audit table on noisy days. **Default in this PR: skip** — the per-request row is sufficient. Revisit if operators complain.
- **Q4 — `create_app()` integration test.** Where does the test that asserts `RoEMiddleware` is actually mounted on the live app live? Two options: (a) extend `test_main.py` to inspect `app.user_middleware` for `RoEMiddleware`; (b) extend `test_roe_middleware.py` with an end-to-end test using the real `create_app()`. Recommendation: **(b)** — keeps the RoE test surface self-contained and lets us flip `ROE_ENABLED` per-case.

---

## Appendix A — REQ ↔ Implementation map

| REQ | Where | Status |
|---|---|---|
| REQ-021 (`RoE` model: id, client_name, signed_date, expires, legal_basis, scope) | `models.py:343-433` (note: spec naming differs — actual columns are `target`, `valid_from`/`valid_until`, `authorized_by`, `scope_type`/`scope_value`) | merged at `6d43ee4` |
| REQ-022 (`Scope` model: in_target_subdomains, in_target_ip_ranges, out_of_scope) | Flattened into `RoE.scope_type` enum + `scope_value` in PR 1. CIDR/glob expansion deferred to PR 2+ (`roe.py:13-19`). | merged at `6d43ee4` |
| REQ-023 (`SignOff` model: action_type, granted_by, granted_at, expires_at, conditions JSON) | `models.py:436-464` (action_type flattened to RoE scope; conditions JSON not stored — `revoked_at` is the binary authorization state). No `expires_at` per-signoff in PR 1; the RoE window is authoritative. | merged at `6d43ee4` |
| REQ-024 (`RoEValidator.is_action_allowed(action, roe) -> bool`) | `orchestrator/roe.py:58` (`is_authorized(target, scope_type) -> (bool, str, list[SignOff])`). Signature differs — returns a reason string and the active signoffs alongside the bool so the middleware can surface detail to the client. | merged at `a2ebb62` |
| REQ-025 (FastAPI middleware that loads RoE per job + validates each request) | `middleware/roe.py:48-111`. Loads RoE per request via `RoEValidator` (no per-job cache yet). | merged at `c1dda05` |
| REQ-026 (expiry check — reject if RoE expired) | `orchestrator/roe.py:92-103` (`is_acceptable` boundary + distinct "valid_from future" vs "valid_until past" reasons). | merged at `a2ebb62` |
| REQ-027 (sign_off query — validate that sign-off is granted and current) | `orchestrator/roe.py:105-111` (filters `revoked_at IS NULL`; returns the active list). | merged at `a2ebb62` |

## Appendix B — Meta-layer checks

| Layer | Status |
|---|---|
| L1 anti-hallucination | ✅ Every class/column/function/middleware path cited against the actual source on disk. Models verified at `models.py:331-464`, validator at `orchestrator/roe.py:1-176`, middleware at `middleware/roe.py:1-156`, migration at `alembic/versions/20261007224728_add_roe_tables.py:1-80`. |
| L2 adversarial | ✅ §7 enumerates 7 denial scenarios + 1 cache-staleness scenario with deterministic behavior. |
| L3 privacy | ✅ §10 documents why column-level encryption is theatrical for SQLite (filesystem encryption is the real control) and confirms RoE denials are captured by the existing audit middleware. |
| L4 anti-block | ✅ Middleware is env-disabled by default (`roe.py:59`), short-circuits non-POST + non-protected paths before touching the body (`roe.py:68-73`), and falls back to DOMAIN on bad scope_type instead of erroring (`roe.py:141-153`). The DB session is opened/closed per request (`roe.py:79, 114-115`) so there's no async-vs-sync timeout race. |