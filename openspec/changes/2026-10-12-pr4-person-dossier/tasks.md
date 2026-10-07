# PR 4 — person_dossier — Tasks (TDD-ordered)

> Strict TDD: each task is RED → GREEN → REFACTOR.
> Verify after each task: pytest passes, mypy --strict passes, ruff check passes.

## Tasks

### Task 1: Tests for FindingType.DOSSIER
- [ ] Add `DOSSIER = "dossier"` to `FindingType` enum in `backend/app/models.py`
- [ ] Write `tests/test_models.py::test_finding_type_dossier_value` — RED
- [ ] Run pytest, confirm RED
- [ ] Verify enum exists, GREEN

### Task 2: Tests for IdentityMap model
- [ ] Add `IdentityMap` SQLAlchemy model to `backend/app/models.py`
  - Columns: id, job_id (FK), email_hash (PK), encrypted_email (bytes), source_modules (JSON list), created_at
  - Unique constraint on (job_id, email_hash)
- [ ] Write tests for model — RED
- [ ] Verify model exists, GREEN
- [ ] Verify migration generates correctly

### Task 3: Tests for PersonDossier Pydantic schema
- [ ] Create `PersonDossier` Pydantic model in `backend/app/modules/person_dossier.py`
  - Fields: email_hash, pseudonym, profiles[], breach_exposures[], role_relevance, priority_for_targeting, aggregated_confidence, source_modules[]
- [ ] Write schema tests — RED
- [ ] Verify schema works with valid input, GREEN
- [ ] Test Pydantic extra="forbid" rejects unknown fields

### Task 4: Tests for email_hash extraction
- [ ] Implement `_extract_email_hash(finding)` in person_dossier.py
- [ ] Tests: extract from EMAIL finding value, extract from metadata.email_hash, normalize case
- [ ] RED → GREEN

### Task 5: Tests for group_by_email_hash
- [ ] Implement `_group_by_email_hash(findings) -> dict[email_hash, list[Finding]]`
- [ ] Tests: groups by hash, handles missing email_hash, empty list
- [ ] RED → GREEN

### Task 6: Tests for confidence aggregation
- [ ] Implement `_aggregate_confidence(findings) -> float`
- [ ] Test: 1 source = source confidence, 2+ sources = max + 0.1, capped at 1.0
- [ ] RED → GREEN

### Task 7: Tests for encryption helper
- [ ] Create `backend/app/utils/encryption.py` with:
  - `hash_email(email: str) -> str` (SHA-256)
  - `encrypt_email(email: str, key: bytes) -> bytes` (Fernet)
  - `decrypt_email(token: bytes, key: bytes) -> str`
- [ ] Tests: round-trip works, wrong key fails, tampering fails
- [ ] RED → GREEN

### Task 8: Tests for cross-module correlation AI call
- [ ] Implement `_ai_coherence_check(person_dossier, llm) -> dict`
- [ ] Tests: with stub LLM, with real LLM (skipped in CI), JSON parse error handling
- [ ] Mock MiniMax-M3 response
- [ ] RED → GREEN

### Task 9: Tests for run() method (orchestrator integration)
- [ ] Implement `PersonDossierModule.run(input) -> ModuleOutput`
- [ ] Tests:
  - Empty findings → returns empty output
  - 1 source (email) → 1 dossier with confidence=source_conf
  - 2 sources (email) → 1 dossier with confidence=max+0.1
  - 3 sources (email) → 1 dossier (no further confidence escalation)
  - Email casing differences → normalized before hashing
  - Missing email_hash → filtered out
  - LLM malformed JSON → graceful fallback to MEDIUM coherence
- [ ] RED → GREEN (mock all external deps)

### Task 10: Tests for Idempotency
- [ ] Verify running twice on same job_id produces same dossier (idempotency)
- [ ] Test: insert twice → unique constraint blocks duplicate
- [ ] GREEN

### Task 11: Register module in MODULE_REGISTRY
- [ ] Add `PersonDossierModule` to `MODULE_REGISTRY` dict in `backend/app/modules/__init__.py`
- [ ] Set `touch_classification` and `requires_consent` appropriately
- [ ] GREEN (no code change, just registration)

### Task 12: Update handoff schema with person_dossiers[]
- [ ] Add `person_dossiers: list[PersonDossierSummary]` to `HandoffPacket` schema in `backend/app/handoff/schema.py`
- [ ] Update exporter in `backend/app/handoff/exporter.py` to extract dossiers from job's findings
- [ ] GREEN

### Task 13: Update frontend ModuleCard to show person_dossier
- [ ] In `frontend/src/components/ModuleCard.tsx`, add person_dossier entry (or create new ModuleCatalog)
- [ ] GREEN

### Task 14: Run full test suite
- [ ] Run `cd backend && DATABASE_URL="sqlite:///:memory:" python -m pytest tests/ --cov=app --cov-fail-under=90`
- [ ] Run `mypy app/ --strict`
- [ ] Run `ruff check app/`
- [ ] Run `grep -ri "Dragonjar\|JAIME" --exclude-dir=.git .` → 0

### Task 15: Alembic migration
- [ ] Create `backend/alembic/versions/<timestamp>_add_person_dossier.py`
- [ ] Upgrade: add `identity_maps` table
- [ ] Downgrade: drop `identity_maps` table
- [ ] Test: `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`

### Task 16: Final commit + session log
- [ ] Conventional commit: `feat(modules): add person_dossier aggregator (Tier 3, gated)`
- [ ] Create session log: `mindos/folio/40_proyectos/zimlama-recon/wiki/sesiones/2026-10-12-pr4-person-dossier.md`

## Definition of Done
- All tasks checked
- pytest --cov-fail-under=90 passes
- mypy --strict passes
- ruff check passes
- 0 DragonJar / JAIME RESTREPO mentions
- No Co-Authored-By in commit messages
- Conventional commit message
- Session log created