# PR 1 — RoE model + middleware + validator — Tasks (TDD-ordered)

> **Strict TDD**: each task is RED → GREEN → REFACTOR.
> Most work already merged (`6d43ee4`, `a2ebb62`, `c1dda05`, `7f198fb`). Only REQ-021a (wiring) + REQ-028 (settings visibility) remain.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~90 LOC across 5 files |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Delivery strategy | single-pr |
| Chain strategy | size:exception |

```text
Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size:exception
400-line budget risk: Low
```

## Tasks

### Task 0 — Verification only (NO new code)

- [ ] 0.1 Confirm `RoEStatus`/`ScopeType`/`RoE`/`SignOff` at `backend/app/models.py:343-464`
- [ ] 0.2 Confirm `RoEValidator` at `backend/app/orchestrator/roe.py:41-176` (`is_authorized` line 58, `_find_candidate` line 149)
- [ ] 0.3 Confirm `RoEMiddleware` at `backend/app/middleware/roe.py:48-156` (env flag line 59, default paths lines 42-45)
- [ ] 0.4 Confirm migration `backend/alembic/versions/20261007224728_add_roe_tables.py` has `upgrade()` + `downgrade()`
- [ ] 0.5 Confirm 29 existing tests pass (model:5 + validator:10 + middleware:14)
- [ ] 0.6 Confirm `ROE_ENABLED` is NOT yet in `backend/app/config.py:Settings` (proves the gap)

### Task 1 — RED: Wiring tests for `create_app()` (REQ-021a, AC-021a.1–.3)

- [ ] 1.1 Create `backend/tests/test_app_wiring.py` (Apache-2.0 header)
- [ ] 1.2 `test_roe_middleware_loaded_when_enabled`: `ROE_ENABLED=true` → `RoEMiddleware` in `app.user_middleware`, positioned AFTER CORSMiddleware and BEFORE AuditLogMiddleware
- [ ] 1.3 `test_roe_middleware_absent_when_disabled`: default → middleware absent
- [ ] 1.4 `test_roe_middleware_absent_on_invalid_env_value`: `ROE_ENABLED=NotABool` → middleware absent (no crash)
- [ ] 1.5 `test_session_factory_is_callable`: middleware's `session_factory` arg is callable, equals `SessionLocal`, NOT a `Session` instance
- [ ] 1.6 RED: `cd backend && pytest tests/test_app_wiring.py -q` → MUST fail (no wiring yet)

### Task 2 — GREEN: Wire `RoEMiddleware` into `create_app()` (REQ-021a)

- [ ] 2.1 In `backend/app/main.py`, add imports: `from app.database import SessionLocal` + `from app.middleware.roe import RoEMiddleware`
- [ ] 2.2 After `app.add_middleware(CORSMiddleware, ...)` (line 133) and BEFORE `if settings.AUDIT_LOGGING_ENABLED` (line 136), insert:

```python
    # Rules-of-Engagement enforcement (REQ-021a, env-disabled by default).
    if settings.ROE_ENABLED:
        app.add_middleware(RoEMiddleware, session_factory=SessionLocal)
```

- [ ] 2.3 GREEN: re-run `pytest tests/test_app_wiring.py -q` → all 5 pass
- [ ] 2.4 Re-run `pytest tests/test_roe_*.py tests/test_app_wiring.py -q` → 29 existing + 5 new = 34 pass

### Task 3 — RED: End-to-end integration tests (REQ-021a AC-021a.4)

- [ ] 3.1 Create `backend/tests/test_roe_middleware_integration.py` (Apache-2.0 header)
- [ ] 3.2 `test_roe_enabled_no_roe_db_returns_403`: `ROE_ENABLED=true`, empty RoE DB, `POST /api/v1/jobs {target:"example.com"}` → 403 + `{"error": "roe_not_authorized", ...}`
- [ ] 3.3 `test_roe_enabled_with_active_roe_passes`: seed ACTIVE RoE + 1 un-revoked SignOff → POST → handler reaches route (200/422 — not 403/500)
- [ ] 3.4 `test_roe_enabled_expired_roe_returns_403`: seed RoE with `valid_until` in past → 403 + detail contains "expired"
- [ ] 3.5 `test_roe_enabled_draft_status_returns_403`: seed `status=DRAFT` RoE → 403 + detail contains "not active"
- [ ] 3.6 `test_roe_enabled_all_signoffs_revoked_returns_403`: ACTIVE RoE + all signoffs have `revoked_at` → 403 + detail contains "no active"
- [ ] 3.7 `test_roe_disabled_passes_through`: `ROE_ENABLED` unset, empty RoE DB → POST succeeds (no-op middleware)
- [ ] 3.8 RED: `pytest tests/test_roe_middleware_integration.py -q` → at least the 201/no-op paths fail (Settings gap)

### Task 4 — GREEN: Add `ROE_ENABLED` to `Settings` (REQ-028)

- [ ] 4.1 In `backend/app/config.py`, append after line 94 (`AUDIT_LOGGING_ENABLED`):

```python
    # ---- RoE enforcement (PR 1, default off) ----
    ROE_ENABLED: bool = Field(
        default=False,
        description=(
            "Enable Rules-of-Engagement enforcement on POST /api/v1/jobs. "
            "When false (default), middleware is a no-op. When true, "
            "requests without an active RoE return 403. Reads at app "
            "construction; flip by restarting the process."
        ),
    )
    ROE_SESSION_FACTORY: str | None = Field(
        default=None,
        description=(
            "Optional dotted path to override SessionLocal in RoEMiddleware."
        ),
    )
```

- [ ] 4.2 GREEN: `pytest tests/test_roe_middleware_integration.py tests/test_app_wiring.py -q` → all pass
- [ ] 4.3 Verify `from app.config import get_settings; get_settings().ROE_ENABLED is False`

### Task 5 — DOC: Document in `.env.example`

- [ ] 5.1 Append to `backend/.env.example`:

```bash
# -----------------------------------------------------------------------------
# Rules-of-Engagement enforcement (PR 1)
# When true, RoEMiddleware enforces scope + sign-off on POST /api/v1/jobs.
# Read once at app construction; flip by restarting.
# -----------------------------------------------------------------------------
# ROE_ENABLED=false
# ROE_SESSION_FACTORY=
```

### Task 6 — REFACTOR (optional)

- [ ] 6.1 If `create_app()` body exceeds ~50 LOC after Task 2.2, extract middleware stack (CORS + RoE + Audit) into private `_register_middlewares(app)` helper in `backend/app/main.py`. Public signature unchanged.
- [ ] 6.2 Re-run full suite — no behavior change.

### Task 7 — Verification + lint + coverage

- [ ] 7.1 `cd backend && DATABASE_URL="sqlite:///:memory:" python -m pytest tests/ --cov=app --cov-fail-under=90 -q` → exits 0
- [ ] 7.2 Coverage ≥ 90% (29 existing + 5 wiring + 6 integration = 40 RoE-touching tests)
- [ ] 7.3 `cd backend && python -m alembic upgrade head && python -m alembic downgrade -1 && python -m alembic upgrade head` → exits 0 (reversibility)
- [ ] 7.4 `cd backend && mypy app/ --strict` → no new errors
- [ ] 7.5 `cd backend && ruff check app/ tests/test_app_wiring.py tests/test_roe_middleware_integration.py` → no new errors

### Task 8 — Final checks + commit

- [ ] 8.1 `grep -ri "Dragonjar\|JAIME" backend/app/main.py backend/app/config.py backend/app/middleware/ backend/.env.example backend/tests/test_app_wiring.py backend/tests/test_roe_middleware_integration.py` → 0
- [ ] 8.2 Apache-2.0 header on every new file
- [ ] 8.3 No `Co-Authored-By` in any commit
- [ ] 8.4 Commit sequence (one logical step per commit):
  - `test(app): wiring + integration tests for RoEMiddleware mount (REQ-021a)` (Task 1 + Task 3 RED)
  - `feat(middleware): wire RoEMiddleware into create_app() (REQ-021a)` (Task 2 GREEN)
  - `feat(config): expose ROE_ENABLED + ROE_SESSION_FACTORY in Settings (REQ-028)` (Task 4 GREEN)
  - `docs(env): document ROE_ENABLED + ROE_SESSION_FACTORY in .env.example` (Task 5)
  - `docs(sdd): PR 1 RoE tasks` (this file)
- [ ] 8.5 Update `wiki/MEMORY.md` and session log if any architectural decision was recorded

## Definition of Done

- All 8 tasks checked
- `pytest --cov-fail-under=90` exits 0 with ≥ 90% coverage
- `mypy --strict` exits 0
- `ruff check` exits 0
- 0 DragonJar / JAIME RESTREPO references
- No `Co-Authored-By` in commits
- Conventional commits only
- Middleware env-disabled by default (backward compat)
- Registration order: CORS → RoE → Audit
- Migration reversibility verified
- Session log updated