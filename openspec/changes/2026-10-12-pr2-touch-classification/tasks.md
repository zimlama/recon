# PR 2 — touch_classification — Tasks (TDD-ordered)

> **Strict TDD**: each task RED → GREEN → REFACTOR.
> Existing modules already declare `tier` (low risk) and `requires_consent` (free API audit done in PR 1).
> This PR adds `TouchClass` enum + `touch_classification` + `requires_paid` attrs and a registry filter.
>
> **Source-verified mapping table**: see `spec.md` REQ-029 (file:line citations re-checked 2026-10-12).
> **Default values**: per spec REQ-028, `tools_only_free` defaults to **`True`** (NOT `False`) — keep in sync with `spec.md` line 156 + scenario line 187.

---

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~180-260 (15 source files + 1 new test file) |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR (PR 2 of the v0.1.1 person-OSINT plan) |
| Delivery strategy | ask-on-risk |
| Chain strategy | n/a (single PR) |

```text
Decision needed before apply: Yes
Chained PRs recommended: No
Chain strategy: n/a
400-line budget risk: Low
```

---

## Phase 1: Foundation — TouchClass enum + BaseReconModule attrs

### Task 1.1 — RED: parametrize TouchClass enum tests
- [ ] Create `backend/tests/test_touch_classification.py` (new file)
- [ ] Write `test_touch_class_has_four_members` — assert only `PASSIVE_TARGET`, `PASSIVE_THIRDPARTY`, `ACTIVE_TARGET`, `ACTIVE_THIRDPARTY` exist
- [ ] Write `test_touch_class_is_str_enum` — assert `TouchClass.PASSIVE_TARGET == "passive_target"` and `isinstance(..., str) is True`
- [ ] Write `test_touch_class_rejects_unknown` — assert `pydantic.ValidationError` on unknown value when used as Pydantic field type
- [ ] Write `test_touch_class_is_io_free_at_import` — assert `import app.modules.base` makes zero network calls (mock `httpx`)
- [ ] Run `cd backend && DATABASE_URL="sqlite:///:memory:" python -m pytest tests/test_touch_classification.py` — confirm **RED** (4 fails)

### Task 1.2 — GREEN: add `TouchClass` enum to `backend/app/modules/base.py`
- [ ] Add `from enum import Enum` import (top of file)
- [ ] Define `class TouchClass(str, Enum)` with 4 members (`PASSIVE_TARGET="passive_target"`, etc.) per spec REQ-028
- [ ] Run tests — confirm **GREEN**

### Task 1.3 — RED: test class attrs on `BaseReconModule`
- [ ] Add `test_base_module_default_touch_class` — assert default is `TouchClass.PASSIVE_TARGET`
- [ ] Add `test_base_module_default_requires_paid` — assert default is `False`
- [ ] Run tests — confirm **RED**

### Task 1.4 — GREEN: add class attrs to `BaseReconModule`
- [ ] In `backend/app/modules/base.py`, add after line 80 (after `enabled_by_default`):
  ```python
  touch_classification: TouchClass = TouchClass.PASSIVE_TARGET
  requires_paid: bool = False
  ```
- [ ] Run tests — confirm **GREEN**

### Task 1.5 — REFACTOR
- [ ] Verify `mypy --strict` accepts both attrs (no `var-annotated` warnings)
- [ ] Add docstring comment on `TouchClass` linking to `spec.md` REQ-028

---

## Phase 2: Module Mapping Table (14 modules)

### Task 2.1 — RED: parametrized mapping test (touch_classification + requires_paid)
- [ ] In `backend/tests/test_touch_classification.py`, write `test_module_touch_classification` parametrized over the 14-module table in spec REQ-029
- [ ] Write `test_module_requires_paid_false` parametrized over all 14 modules asserting `False`
- [ ] Import each module class from `app.modules` and read the attr
- [ ] Run tests — confirm **RED** (28 fails: all modules default to `PASSIVE_TARGET` / `False`)

### Task 2.2 — GREEN: update the 14 module files
For each module below, add the two class attrs in the class body (before `__init__` or alongside `tier`):

| Module | `touch_classification` | `requires_paid` | Source file |
|---|---|---|---|
| `whois_rdap` | `PASSIVE_TARGET` | `False` | `backend/app/modules/whois_rdap.py` |
| `dns_enum` | `ACTIVE_TARGET` | `False` | `backend/app/modules/dns_enum.py` |
| `subdomain_enum` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/subdomain_enum.py` |
| `certificate_transparency` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/certificate_transparency.py` |
| `wayback_machine` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/wayback_machine.py` |
| `email_harvesting` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/email_harvesting.py` |
| `shodan_censys` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/shodan_censys.py` |
| `github_recon` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/github_recon.py` |
| `google_dorking` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/google_dorking.py` |
| `metadata_analysis` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/metadata_analysis.py` |
| `breach_data` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/breach_data.py` |
| `socmint` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/socmint.py` |
| `employee_osint` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/employee_osint.py` |
| `dark_web_osint` | `PASSIVE_THIRDPARTY` | `False` | `backend/app/modules/dark_web_osint.py` |

- [ ] Run tests after each module — confirm 28 passes (GREEN)
- [ ] Add `from app.modules.base import TouchClass` import where missing

### Task 2.3 — REFACTOR
- [ ] Verify no module is left without the attrs (run `rg -L "touch_classification" backend/app/modules/*.py` → empty)
- [ ] Confirm `mypy --strict` still clean

---

## Phase 3: Config — `tools_only_free` field

### Task 3.1 — RED: test `Settings.tools_only_free` parsing
- [ ] In `backend/tests/test_touch_classification.py`, write:
  - `test_tools_only_free_default_true` (env unset → `True`)
  - `test_tools_only_free_explicit_false` (`TOOLS_ONLY_FREE=false` → `False`)
  - `test_tools_only_free_invalid_string_falls_back` (`TOOLS_ONLY_FREE=maybe` → falls back to `True` OR raises; per spec L217, NEVER silently `False`)
- [ ] Run tests — confirm **RED**

### Task 3.2 — GREEN: add field to `Settings`
- [ ] In `backend/app/config.py`, add (after `# ---- Feature flags ----` block):
  ```python
  tools_only_free: bool = Field(
      default=True,
      description="When True, paid modules (requires_paid=True) are excluded from MODULE_REGISTRY.",
  )
  ```
- [ ] Run tests — confirm **GREEN**

### Task 3.3 — Update `backend/.env.example`
- [ ] Add section (alongside existing optional API keys / feature flags):
  ```bash
  # --- Free tools only ---
  # When true, modules with requires_paid=True are excluded from MODULE_REGISTRY at startup.
  # tools_only_free=true
  ```

### Task 3.4 — REFACTOR
- [ ] Verify `Settings` parses with current `.env` (no regression)

---

## Phase 4: Registry Filter — `_build_registry()`

### Task 4.1 — RED: parametrize filter tests
- [ ] In `backend/tests/test_touch_classification.py`, write:
  - `test_build_registry_excludes_paid_when_tools_only_free_true` (monkeypatch `tools_only_free=True`, set one module `requires_paid=True`, assert it's excluded and `INFO` log captured)
  - `test_build_registry_includes_all_when_tools_only_free_false` (default off, all 14 in registry)
  - `test_build_registry_omitted_requires_paid_defaults_to_false` (module without attr → included)
- [ ] Run tests — confirm **RED**

### Task 4.2 — GREEN: implement filter in `_build_registry()`
- [ ] In `backend/app/modules/__init__.py`, modify `_build_registry()`:
  - After building the 14-entry dict, call `get_settings()` (lazy import to avoid circular dep)
  - If `settings.tools_only_free` and any module has `requires_paid=True`, build filtered dict + log `logger.info("paid_modules_filtered", count=N, modules=[...])`
- [ ] Run tests — confirm **GREEN**
- [ ] Verify `get_module_registry()` signature unchanged (still returns `dict[str, BaseReconModule]`)

### Task 4.3 — REFACTOR
- [ ] Confirm filter is O(n) (no nested loops), no I/O
- [ ] Confirm log message contains only module names (no PII)

---

## Phase 5: Route Rejection + AuditLog

### Task 5.1 — RED: test `POST /jobs` rejects paid module under `tools_only_free=true`
- [ ] In `backend/tests/test_touch_classification.py`, write:
  - `test_post_jobs_rejects_paid_module_under_free_only` — submit job with a paid-only module, monkeypatch registry to include exactly one `requires_paid=True` module + `tools_only_free=True` → expect HTTP 400 with clear detail
  - `test_post_jobs_paid_rejection_writes_audit_log` — same request, assert exactly one `AuditLog` row with `action="module_paid_rejected"` and `details={"module": ..., "reason": "tools_only_free=true"}`
  - `test_repeated_rejections_create_one_audit_row_each` — 5 rejections → 5 audit rows
  - `test_no_boot_time_audit_row_when_no_job` — import app → zero `module_paid_rejected` rows
- [ ] Run tests — confirm **RED**

### Task 5.2 — GREEN: add validation branch in `backend/app/routes/jobs.py`
- [ ] After the existing module-name validation (currently `routes/jobs.py:36-42`), BEFORE the typed_confirmation check, add:
  ```python
  from app.config import get_settings
  from app.models import AuditLog

  settings = get_settings()
  if settings.tools_only_free:
      for m in payload.selected_modules:
          mod = MODULE_REGISTRY.get(m)
          if mod is not None and mod.requires_paid:
              db.add(AuditLog(
                  action="module_paid_rejected",
                  target=payload.target,
                  details={"module": m, "reason": "tools_only_free=true"},
              ))
              db.commit()
              raise HTTPException(
                  status_code=400,
                  detail=f"Module '{m}' requires paid API and tools_only_free=true",
              )
  ```
- [ ] Run tests — confirm **GREEN**

### Task 5.3 — REFACTOR
- [ ] Ensure `AuditLog` import is clean (no circular)
- [ ] Confirm `db.commit()` happens before the `HTTPException` (audit row must persist even on error)

---

## Phase 6: Test Suite + Lint + Type Check

### Task 6.1 — Full test suite + 90% coverage gate
- [ ] Run `cd backend && DATABASE_URL="sqlite:///:memory:" python -m pytest tests/ --cov=app --cov-fail-under=90`
- [ ] All tests pass; coverage ≥ 90% maintained

### Task 6.2 — mypy strict
- [ ] Run `cd backend && mypy app/ --strict` — zero errors

### Task 6.3 — ruff
- [ ] Run `cd backend && ruff check app/ tests/` — zero errors

---

## Phase 7: Frontend + Compliance

### Task 7.1 — `ModuleCard.tsx` (optional, covered by spec REQ-016 PR 4 task 11)
- [ ] If badge is in scope for PR 2: add a `paid`/`free` badge next to existing `tier` badge in `frontend/src/components/ModuleCard.tsx`
- [ ] Otherwise defer to PR 4 — leave a `// TODO(pr4): add paid/free badge` comment

### Task 7.2 — Compliance sweep
- [ ] Run the DragonJar-leak guard (see project root `.claude/rules/no-pii-leak.md` if present) over all changed paths → **0 hits**
- [ ] Apache-2.0 LICENSE header present on every new file (verify `test_touch_classification.py`)
- [ ] No `Co-Authored-By:` lines in any commit

---

## Phase 8: Commit + Close

### Task 8.1 — Conventional commits (split per work unit)
- [ ] `git add backend/app/modules/base.py && git commit -m "feat(modules): add TouchClass enum + touch_classification/requires_paid on BaseReconModule"`
- [ ] `git add backend/app/config.py backend/.env.example && git commit -m "feat(config): add tools_only_free setting"`
- [ ] `git add backend/app/modules/*.py && git commit -m "feat(modules): classify all 14 modules per spec REQ-029 mapping table"`
- [ ] `git add backend/app/modules/__init__.py && git commit -m "feat(modules): filter MODULE_REGISTRY by tools_only_free"`
- [ ] `git add backend/app/routes/jobs.py && git commit -m "feat(routes): reject paid modules in POST /jobs when tools_only_free=true + AuditLog row"`
- [ ] `git add backend/tests/test_touch_classification.py && git commit -m "test(modules): cover TouchClass enum, mapping table, filter, AuditLog"`
- [ ] `git add openspec/changes/2026-10-12-pr2-touch-classification/tasks.md && git commit -m "docs(sdd): PR 2 touch_classification tasks"`

### Task 8.2 — Open PR to `developer` branch
- [ ] Branch is already `developer` — `gh pr create --base develop` (or merge directly per project policy)
- [ ] PR title: `feat(modules): PR 2 — TouchClass enum + tools_only_free registry filter`
- [ ] PR body links to `openspec/changes/2026-10-12-pr2-touch-classification/`

### Task 8.3 — Archive change
- [ ] After merge, run `openspec archive 2026-10-12-pr2-touch-classification --yes` (if available) OR copy delta spec to `openspec/specs/modules/spec.md`

---

## Definition of Done

- [ ] All tasks in Phases 1-8 checked
- [ ] `pytest --cov-fail-under=90` passes
- [ ] `mypy --strict` passes
- [ ] `ruff check` passes
- [ ] DragonJar-leak guard returns 0 across all changed files
- [ ] No `Co-Authored-By:` in any commit
- [ ] Conventional commits only
- [ ] Mapping table is source-verified (file:line citations match `spec.md` REQ-029)
- [ ] All 14 modules declare correct `touch_classification` + `requires_paid`
- [ ] `POST /jobs` returns HTTP 400 + writes `AuditLog` when paid module is rejected
- [ ] `MODULE_REGISTRY` filter is O(n), deterministic, no I/O

---

## Open Questions Resolved (from `spec.md` L336-344)

| # | Resolution |
|---|---|
| Q1 | `dark_web_osint._search_via_tor` stays `PASSIVE_THIRDPARTY` (Tor fetch is read-only HTTP) |
| Q2 | `ACTIVE_THIRDPARTY` reserved for PR 7+ (forward-compat slot, no current occupant) |
| Q3 | `AuditLog` rows written **per-job attempt**, not at boot |
| Q4 | `dns_enum` AXFR warning UX deferred to PR 3 (harness layer) |

## Cross-References

- `openspec/changes/2026-10-12-pr2-touch-classification/proposal.md` — intent + scope
- `openspec/changes/2026-10-12-pr2-touch-classification/spec.md` — REQ-028 to REQ-029 (source of truth)
- `openspec/changes/2026-10-12-pr2-touch-classification/design.md` — architecture decisions + mapping table
- `backend/app/modules/base.py:58-80` — `BaseReconModule` class metadata block (insertion point for new attrs)
- `backend/app/config.py:91-94` — Feature flags section (insertion point for `tools_only_free`)
- `backend/app/modules/__init__.py:35-58` — `_build_registry()` (insertion point for filter)
- `backend/app/routes/jobs.py:36-42` — module-name validation (insertion point for paid-module rejection)
- `backend/app/models.py:314-328` — `AuditLog` schema (no migration needed)