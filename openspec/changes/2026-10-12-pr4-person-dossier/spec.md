# PR 4 — person_dossier aggregator — Specification (Delta)

> **Change**: `2026-10-12-pr4-person-dossier`
> **Phase**: Spec (delta over existing behavior)
> **Source design**: `openspec/changes/2026-10-12-pr4-person-dossier/design.md`
> **Source plan**: `wiki/sesiones/2026-10-07-plan-mejoras-person-osint.md` (PR 4)
> **Coverage target**: 90% (`pytest --cov-fail-under=90`)

This is the **delta spec** for PR 4. It only enumerates the requirements PR 4
adds / modifies against the current recon behavior. Existing module contracts
(`BaseReconModule`, `Finding`, `FindingType`, `Job`, `ModuleRun`) are
referenced, not copied. See design.md §11 for the full integration file map.

**Meta-layer summary** (per design.md Appendix B + §6-§9):

| Layer | How each REQ addresses it |
|---|---|
| L1 anti-hallucination | Every REQ verified against `models.py`, `base.py`, `breach_data.py`, `prompts.py` — REQ-016/018 cite the `FindingType` enum and `BaseReconModule` directly. |
| L2 adversarial | Each REQ carries an **Adversarial scenarios** sub-block (malformed JSON, casing, missing siblings, encryption-key absence, timeout). |
| L3 privacy | Each REQ carries a **Privacy** classification: `NONE`, `INTERNAL`, `PII`, `SENSITIVE`. The plaintext email never crosses `_resolve_plaintext_email` except into Fernet ciphertext (REQ-020). |
| L4 anti-block | Each REQ carries **Anti-block** constraints: bounded SQL `LIMIT 10000`, per-dossier AI cap `MAX_TOKENS=256`, `temperature=0.1`, 30s `asyncio.wait_for`, no subprocess. |

---

## REQ-016: person_dossier module — Tier 3 gated aggregator

- **Priority**: P0 (Tier 3, gated, opt-in)
- **Type**: NEW MODULE
- **Trigger**: runs after `employee_osint`, `socmint`, `breach_data` complete for the same `job_id` (or returns `ModuleStatus.SKIPPED` while any sibling is pending — see Open Question Q1).
- **Inputs**: `ModuleInput.job_id` (UUID v4 string), `target` (domain).
- **Outputs**: `ModuleOutput(findings=[Finding(type=DOSSIER, value=persona_id, ...)], errors=[...])`.
- **MITRE**: `T1589.002` (gather victim email addresses — aggregator over already-gathered data, no new network IO).

The system MUST provide a `PersonDossierModule` subclassing
`BaseReconModule` (per `backend/app/modules/base.py`) with class attributes:

| Attribute | Value | Verified against |
|---|---|---|
| `name` | `"person_dossier"` | `Finding.source` convention (`models.py:233`) |
| `description` | "Cross-module person dossier aggregator — merges findings from socmint, employee_osint, breach_data into one DOSSIER per identity" | `base.py:84` enforces non-empty |
| `phase` | `"01-recon-osint"` | matches `breach_data.py:43` |
| `tier` | `ModuleTier.TIER_3` | `models.py:58-64` |
| `mitre_techniques` | `["T1589.002"]` | `base.py:79` list[str] |
| `requires_api_keys` | `[]` (no network) | `breach_data.py:46` precedent |
| `requires_consent` | `True` (PII handling) | `breach_data.py:47` precedent |
| `enabled_by_default` | `False` (opt-in) | `breach_data.py:49` precedent |
| `estimated_duration_seconds` | `30` (bounded — no network IO) | `base.py:79` `int \| None` |

### Acceptance criteria

- **AC-016.1** — Given a `job_id` where `employee_osint` returns USERNAME `"jane@example.com"`, `socmint` returns SOCIAL_PROFILE `"linkedin.com/in/jane"`, and `breach_data` returns CREDENTIAL_EXPOSURE for `"jane@example.com"` with a 10-char SHA-1 prefix, when `person_dossier.run(input)` executes, it emits **exactly one** `Finding(type=FindingType.DOSSIER, value="Persona_001", ...)` whose `finding_metadata` is a `PersonDossier` aggregating all three sources.
- **AC-016.2** — Given that `email_harvesting` ran for the same `job_id` and emitted an EMAIL finding with `value="jane@example.com"`, when `person_dossier` builds the dossier, it also inserts one row into `identity_map` with `email_hash = hash_email("jane@example.com")` and `encrypted_email = encrypt_email("jane@example.com")` (Fernet ciphertext, NOT plaintext).
- **AC-016.3** — Given that `email_harvesting` did NOT run for the same `job_id`, when `person_dossier` builds the dossier, it emits the DOSSIER Finding with `value="Persona_001_no_pii"` and **does not** insert any `identity_map` row.
- **AC-016.4** — Given `ModuleOutput.findings` contains exactly one DOSSIER for `jane@example.com`, when `person_dossier.run()` is called a second time on the same `job_id` (idempotency), it emits **zero** additional DOSSIER Findings for that email_hash and logs a debug-level message: "dossier already emitted for email_hash=H".
- **AC-016.5** — Given no completed `module_runs` for any of the three SOURCE_MODULES (`employee_osint`, `socmint`, `breach_data`) on `job_id`, when `person_dossier.run()` executes, it returns `ModuleOutput(findings=[], errors=["no completed sibling modules"])`. No DOSSIER emitted. No `identity_map` row written.
- **AC-016.6** — Given a job with one completed sibling (e.g. only `breach_data`), when `person_dossier.run()` executes, it still emits one DOSSIER per email_hash found in that sibling. `source_modules = ["breach_data"]` (single element). Confidence = max of source confidences (no boost, per AC-019.2).
- **AC-016.7** — `PersonDossierModule` MUST be registered in `backend/app/modules/__init__.py` MODULE_REGISTRY under the `"person_dossier"` key (per the registry pattern at `__init__.py:35-55`).

### Adversarial scenarios

- **A-016.a — Sibling ModuleRun still RUNNING**: one of `employee_osint` / `socmint` / `breach_data` has `ModuleStatus.RUNNING` (not COMPLETED). `person_dossier` MUST either wait-poll and retry, or return `ModuleStatus.SKIPPED` with errors=["sibling still running"]. **Behavior TBD per Open Question Q1 — choose before implementation.**
- **A-016.b — ModuleRunner crash mid-flight**: one sibling has `ModuleStatus.FAILED`. `person_dossier` MUST skip that sibling's findings (already excluded by the `status == COMPLETED` filter in `_query_sibling_findings`) and proceed with the remaining siblings.
- **A-016.c — Same dossier emitted twice in same run**: bucket iteration produces a duplicate `email_hash` (e.g. one EMAIL finding + one derived hash). The second emission MUST be suppressed by `_already_dossiered_email_hashes` (which tracks in-run as well as DB rows). Test: `test_run_no_duplicate_dossiers_in_same_run`.
- **A-016.d — ModuleRun row missing but Finding row exists** (orphan Finding): `person_dossier` MUST NOT emit a DOSSIER for the orphan Finding — `_query_sibling_findings` joins `module_runs` and only returns Findings whose `module_runs.status == COMPLETED`.
- **A-016.e — Job not found**: `job_id` does not exist in `jobs` table. `person_dossier.run()` MUST re-raise `ValueError("job not found: {job_id}")` (matches `base.py:178` precedent for invalid targets). Caller (`job_runner.py`) catches and writes to `ModuleOutput.errors`.
- **A-016.f — finding_metadata corrupted JSON in DB**: existing Finding has `finding_metadata` that doesn't deserialize. `_extract_email_hash` MUST return `None` for that Finding (defensive — `try/except` around `dict.get`).

### Privacy

- **PII** — the module aggregates findings whose inputs may contain plaintext emails (EMAIL findings from `email_harvesting`). The plaintext is scoped to `_resolve_plaintext_email` and ONLY flows into `encrypt_email`. It is never logged, never written to `Finding.finding_metadata`, never sent to the LLM (which only sees `email_hash`). See REQ-020 for the encryption contract.

### Anti-block

- **No subprocess / no network IO** — `person_dossier` is a pure-DB read aggregator. `estimated_duration_seconds = 30` is a generous upper bound.
- **Bounded SQL** — `_query_sibling_findings` MUST use `LIMIT 10000` on both the `module_runs` subquery and the `findings` outer query.
- **Bounded AI** — one call per dossier (`MAX_TOKENS=256`, `temperature=0.1`, `timeout=30s` via `asyncio.wait_for`). Worst-case per-job: 1000 dossiers × 256 tokens = 256k tokens.

### Failure modes (per design.md §6)

| Scenario | Required behavior |
|---|---|
| MiniMax-M3 returns malformed JSON | `_assess_coherence` catches `ValidationError`, sets `coherence=None`, dossier still emitted with `confidence` from `_compute_confidence`. No retry. |
| MiniMax-M3 unavailable / timeout | Stub mode (`MINIMAX_API_KEY=test-dummy`) returns `recommended_action=CONTINUE` with empty verdicts. `coherence=None`. Dossier still produced. |
| All 3 source modules failed | `ModuleOutput(findings=[], errors=["no completed sibling modules"])`. No DOSSIER. |
| `PERSON_DOSSIER_ENCRYPTION_KEY` env var missing | `_store_identity_map` raises `EncryptionKeyMissingError`; dossier still emitted; `errors` includes "encryption key missing — identity_map row skipped". |

### Files affected

- **NEW** `backend/app/modules/person_dossier.py` — `PersonDossierModule` class (~470 lines)
- **NEW** `backend/app/utils/encryption.py` — `hash_email()`, `encrypt_email()` (~90 lines, Fernet)
- **MODIFY** `backend/app/modules/__init__.py` — register `PersonDossierModule` (add 1 import + 1 registry entry)
- **MODIFY** `backend/app/models.py` — add `FindingType.DOSSIER` enum value + `IdentityMap` SQLAlchemy table
- **MODIFY** `backend/app/llm/prompts.py` — add `PROMPT_PERSON_DOSSIER` + register in `PROMPTS` dict at line 293-308
- **MODIFY** `backend/app/orchestrator/job_runner.py` — honor dependency ordering per Open Question Q1
- **MODIFY** `backend/app/config.py` — add `PERSON_DOSSIER_ENCRYPTION_KEY: str | None` setting
- **MODIFY** `.env.example` — document `PERSON_DOSSIER_ENCRYPTION_KEY`
- **MODIFY** `frontend/src/components/ModuleCard.tsx` — see Open Question Q6 (`ModuleCatalog.tsx` does not exist in this codebase)
- **MODIFY** `docs/MODULE_GUIDE.md` — document `person_dossier` entry
- **NEW** `backend/tests/test_person_dossier.py` — 27 tests (per design.md §11)
- **NEW** `backend/tests/test_encryption.py` — encryption round-trip + Fernet key-rotation tests

---

## REQ-017: email_hash extraction + cross-module grouping

- **Priority**: P0
- **Type**: NEW BEHAVIOR (internal to `person_dossier`)
- **Trigger**: invoked by `_query_sibling_findings` result post-grouping in `run()`.

The system MUST extract a SHA-256 `email_hash` from each sibling Finding via
`_extract_email_hash(finding) -> str | None` with the following deterministic
rules:

| Finding.type | Observation key | Hash source |
|---|---|---|
| `EMAIL` | `finding.value` (raw email) | `hash_email(finding.value)` = `SHA-256(finding.value.strip().lower())` |
| `USERNAME` | `finding.finding_metadata["email_hash"]` (when 64-char SHA-256 hex) | the 64-char string itself |
| `SOCIAL_PROFILE` | `finding.finding_metadata["email_hash"]` (when 64-char SHA-256 hex) | the 64-char string itself |
| `CREDENTIAL_EXPOSURE` | **NOT bucketed per-email** (its 10-char SHA-1 `email_hash_prefix` is rejected by the 64-char length check) | `None` — see REQ-017 AC for domain-join fallback |

Findings with `email_hash == None` MUST be excluded from per-email bucketing
but MAY still be attached via the two-step domain-join in AC-017.4.

### Acceptance criteria

- **AC-017.1** — Given an EMAIL Finding with `value="Jane@Example.com"`, when `_extract_email_hash(finding)` runs, it returns `hashlib.sha256("jane@example.com".encode()).hexdigest()` (lowercased before hashing).
- **AC-017.2** — Given two EMAIL Findings with `values="ja@example.com"` and `"JA@EXAMPLE.COM"`, when bucketing, both land in the same bucket (casing normalized before hash).
- **AC-017.3** — Given a USERNAME Finding with `finding_metadata = {"email_hash": "<64-hex-char>"}`, when `_extract_email_hash(finding)` runs, it returns the 64-char string from `finding_metadata["email_hash"]`. If the value is not exactly 64 chars or contains non-hex characters, return `None`.
- **AC-017.4** — Given a CREDENTIAL_EXPOSURE Finding with `finding_metadata = {"email_hash_prefix": "<10-char-sha1>", "domain": "example.com"}` and an EMAIL Finding in the same `job_id` whose `email_hash` SHA-256 corresponds to the same domain (i.e., the EMAIL value ends with `"@example.com"`), when bucketing, the CREDENTIAL_EXPOSURE Finding's metadata is appended to that dossier's `breach_exposures` list AND its module name is added to `source_modules`.
- **AC-017.5** — Given a CREDENTIAL_EXPOSURE Finding with no matching EMAIL Finding in the same `job_id` (orphan breach), when bucketing completes, the Finding is appended to `ModuleOutput.errors` as `"orphan breach: <email_hash_prefix> for <domain>"` and is NOT emitted as a DOSSIER. Per Open Question Q2, this is the v1 default.
- **AC-017.6** — `_extract_email_hash` MUST return `None` for any Finding whose `type` is not in {EMAIL, USERNAME, SOCIAL_PROFILE, CREDENTIAL_EXPOSURE}. The function MUST NOT raise — unhandled types silently skip.

### Adversarial scenarios

- **A-017.a — Empty string value**: EMAIL Finding with `value=""`. `_extract_email_hash` MUST return `None` (no empty hash written). Test: `test_extract_email_hash_empty_value_returns_none`.
- **A-017.b — Non-email string in EMAIL Finding**: EMAIL Finding with `value="not-an-email"`. The function MUST still hash it (it's a Finding-level responsibility to enforce email format, not a hash-function responsibility). The resulting hash will simply not match any other finding — that's correct behavior.
- **A-017.c — finding_metadata missing key**: USERNAME Finding with `finding_metadata = {"platform_url": "..."}` and NO `"email_hash"` key. Return `None`.
- **A-017.d — finding_metadata is not a dict**: corrupt Finding with `finding_metadata = None`. MUST return `None` (defensive `.get`).
- **A-017.e — Multiple EMAIL findings for same domain but different local-parts**: bucketing produces 2 distinct dossiers (`alice@example.com` vs `bob@example.com`). No false-merge.
- **A-017.f — CREDENTIAL_EXPOSURE with malformed domain**: domain `""` or `None` in metadata. The two-step join MUST skip this entry (no EMAIL matches `""` domain). It becomes an orphan.

### Privacy

- **PII** — `_extract_email_hash` operates on raw `value` for EMAIL findings. This is the ONLY function besides `_resolve_plaintext_email` that touches plaintext email. Both functions are scoped to `person_dossier.py` and the value never escapes to logs/AI/UI.

### Anti-block

- **Bounded bucket size** — `_query_sibling_findings` returns at most `LIMIT 10000` rows, so the bucket map is bounded at 10000 entries. O(n) iteration in step 6 of the algorithm is safe.
- **No regex compilation in hot path** — `_extract_email_hash` does NOT validate email format with regex (regex is unbounded for adversarial inputs); it just lowercases + hashes. Validation belongs in the EMAIL finding emitter, not here.

### Files affected

Same as REQ-016 (helper functions live in `person_dossier.py`).

---

## REQ-018: FindingType.DOSSIER + structured PersonDossier metadata

- **Priority**: P0
- **Type**: SCHEMA EXTENSION

The system MUST add `FindingType.DOSSIER = "dossier"` to the existing
`FindingType` enum at `backend/app/models.py:66-83` (currently 14 values;
adding `DOSSIER` makes 15). This is additive — existing clients that don't
know about `DOSSIER` ignore it gracefully (Pydantic v2 default behavior).

The system MUST introduce `PersonDossier` (Pydantic v2 `BaseModel`,
`extra="forbid"`) embedded inside `Finding.finding_metadata` for every
DOSSIER finding:

```python
class PersonDossier(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email_hash: str                          # SHA-256 hex (REQ-020)
    profiles: list[str]                      # SOCIAL_PROFILE URLs (from socmint)
    breach_exposures: list[dict[str, Any]]   # CREDENTIAL_EXPOSURE metadata
    role_relevance: Literal["HIGH", "MEDIUM", "LOW"]
    priority_for_targeting: Literal["HIGH", "MEDIUM", "LOW"]
    source_modules: list[str]                # unique module names
    confidence: float                        # boosted, capped at 1.0 (REQ-019)
    coherence: str | None = None             # AI-assessed tag, populated post-validation
```

The system MUST store the dossier as `Finding.finding_metadata` (the
`models.py:235` JSON column), NOT as a separate SQLAlchemy relationship.
`Finding.value` for DOSSIER is the `persona_id` string (e.g. `"Persona_001"`).

### Acceptance criteria

- **AC-018.1** — `FindingType.DOSSIER` exists in the enum and is importable as `from app.models import FindingType; FindingType.DOSSIER.value == "dossier"`.
- **AC-018.2** — `PersonDossier.model_dump()` returns a dict with exactly the 8 documented fields, and `PersonDossier(**extra_field=value)` raises `ValidationError` (extra="forbid").
- **AC-018.3** — Every emitted DOSSIER Finding has `finding_metadata` containing all 8 fields. Missing fields (e.g. no breach_exposures) are represented as empty lists, not omitted.
- **AC-018.4** — `Finding(type=FindingType.DOSSIER, value="Persona_001", finding_metadata=<dumped PersonDossier>, source="person_dossier", confidence=<boosted>)` MUST round-trip through `Finding.model_validate(...)` without data loss.
- **AC-018.5** — `PersonDossier.role_relevance` and `priority_for_targeting` are `Literal["HIGH","MEDIUM","LOW"]` — any other value MUST raise `ValidationError`.
- **AC-018.6** — `Finding.type` accepts `FindingType.DOSSIER` without modifying the existing 14 enum values' string representations (additive change only).

### Adversarial scenarios

- **A-018.a — Finding persisted without finding_metadata**: `Finding(type=DOSSIER, value="Persona_001", finding_metadata={})` — SHOULD raise at construction time (Pydantic must enforce the 8-field shape). Defensive check: emit a `logger.warning` if dossier metadata is empty.
- **A-018.b — DB downgrade (Dossier column drop in migration)**: backwards compat — old DB rows with `type="dossier"` but no metadata MUST NOT crash the UI. UI shows "metadata missing" badge. (Not tested in this PR but documented behavior.)
- **A-018.c — Confidence out of range**: `confidence=1.5` (greater than 1.0). MUST raise `ValidationError` (Pydantic `ge=0.0, le=1.0` constraint at `base.py:34`).
- **A-018.d — Non-string email_hash**: `email_hash=b"..."` (bytes). MUST raise `ValidationError` (Pydantic str type). Defensive: also check `len(email_hash) == 64`.

### Privacy

- **PII** — `PersonDossier` has NO `email` field (verified by `extra="forbid"` preventing accidental addition). `email_hash` crosses module boundaries, never plaintext.

### Anti-block

- **Pydantic validation is bounded** — `extra="forbid"` adds a constant-time check per field. For a 8-field schema this is microseconds.
- **No DB migration needed for enum change** — `FindingType` enum is stored as string in SQLite. Adding a new value is additive (per design.md §11, "no public API contract changes").

### Files affected

- **MODIFY** `backend/app/models.py` — append `DOSSIER = "dossier"` to `FindingType` enum (line 66-83)
- **NEW** `backend/app/modules/person_dossier.py` — `PersonDossier` Pydantic class
- **NEW** `backend/tests/test_person_dossier.py` — schema tests

---

## REQ-019: confidence aggregation — max + 0.1 boost, capped at 1.0

- **Priority**: P0
- **Type**: NEW BEHAVIOR (deterministic, no AI involvement)

The system MUST compute dossier confidence via `_compute_confidence(sources)`
where `sources` is the list of `(module_name, Finding)` tuples for one
`email_hash` bucket. The formula MUST be:

```
if not sources: return 0.0
max_conf = max(f.confidence for f in sources)
if len(sources) == 1: return max_conf
return min(max_conf + 0.1, 1.0)
```

Three or more sources use the **same +0.1 boost** as two (per design.md
§5.3, test `test_compute_confidence_three_sources_still_boost`). No further
escalation.

### Acceptance criteria

- **AC-019.1** — Given sources with confidences `[0.6, 0.8]` (2 sources), `_compute_confidence` returns `0.9` (`max + 0.1`).
- **AC-019.2** — Given sources with confidences `[0.6]` (1 source), `_compute_confidence` returns `0.6` (no boost).
- **AC-019.3** — Given sources with confidences `[0.95, 1.0]` (2 sources, `max + 0.1 = 1.05`), `_compute_confidence` returns `1.0` (capped).
- **AC-019.4** — Given sources with confidences `[0.5, 0.7, 0.9]` (3 sources), `_compute_confidence` returns `1.0` (`max=0.9`, `+0.1=1.0`, no further boost).
- **AC-019.5** — Given sources with confidences `[1.0, 1.0, 1.0]` (3 sources, all at ceiling), `_compute_confidence` returns `1.0` (still capped).
- **AC-019.6** — Given an empty source list, `_compute_confidence` returns `0.0` (defensive default — should not happen in practice because the bucketing loop guards on `len(sources) > 0`).

### Adversarial scenarios

- **A-019.a — Negative confidence**: `f.confidence = -0.1` (corrupt DB row). MUST NOT crash the boost. The `max()` will yield `-0.1`, boost is `-0.1 + 0.1 = 0.0`. Acceptable. (Pydantic `ge=0.0` constraint at `base.py:34` SHOULD prevent this — verified at construction time.)
- **A-019.b — NaN confidence**: `f.confidence = float('nan')`. `max()` propagates NaN. `min(nan + 0.1, 1.0) == nan`. SHOULD be caught by Pydantic at construction (`ge=0.0, le=1.0`); if not, dossier confidence is NaN which breaks JSON serialization. Defensive: validate at `_compute_confidence` entry.
- **A-019.c — All sources from the same module** (degenerate case): employee_osint returns 5 USERNAME findings for the same email_hash. They count as 1 source for the boost. `source_modules = ["employee_osint"]`. Test: `test_compute_confidence_same_module_counts_as_one_source`.

### Privacy

- **NONE** — confidence is a derived numeric metric with no PII input.

### Anti-block

- **O(n) where n = sources per email_hash** — bounded by `LIMIT 10000 / (min findings per email_hash)` ≈ worst case 10000 if all sibling findings collapse to one bucket. Acceptable for an in-memory `max()` call.

### Files affected

- **NEW** `backend/app/modules/person_dossier.py` — `_compute_confidence(sources)` helper
- **NEW** `backend/tests/test_person_dossier.py` — confidence aggregation tests

---

## REQ-020: SHA-256 pseudonymization + encrypted IdentityMap

- **Priority**: P0 (CRITICAL — privacy boundary)
- **Type**: NEW TABLE + NEW UTILITIES
- **Privacy classification**: **SENSITIVE** (the entire purpose of this REQ is to keep raw email out of cross-module boundaries)

The system MUST introduce:

1. **NEW** `IdentityMap` SQLAlchemy table in `backend/app/models.py`:

   ```python
   class IdentityMap(Base):
       __tablename__ = "identity_map"
       id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
       job_id: Mapped[str] = mapped_column(
           String(36), ForeignKey("jobs.id", ondelete="CASCADE"),
           nullable=False, index=True,
       )
       email_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
       encrypted_email: Mapped[str] = mapped_column(Text, nullable=False)
       persona_id: Mapped[str] = mapped_column(String(20), nullable=False)
       created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

       __table_args__ = (
           UniqueConstraint("job_id", "email_hash", name="uq_identity_map_job_hash"),
       )
   ```

2. **NEW** `backend/app/utils/encryption.py`:

   - `hash_email(email: str) -> str` — returns `hashlib.sha256(email.strip().lower().encode()).hexdigest()`. 64-char lowercase hex. No salt (deterministic for grouping).
   - `encrypt_email(email: str) -> str` — returns `Fernet(key).encrypt(email.encode()).decode()`. Key sourced from `Settings.PERSON_DOSSIER_ENCRYPTION_KEY` (base64-encoded 32-byte key per Fernet spec).
   - `EncryptionKeyMissingError(Exception)` — raised by `encrypt_email` when the env var is unset or invalid.

4. **NEW** `backend/app/config.py` setting:
   ```python
   PERSON_DOSSIER_ENCRYPTION_KEY: str | None = Field(
       default=None,
       description=(
           "Fernet key for encrypting raw emails in identity_map. "
           "Generate with Fernet.generate_key(). If unset, encryption "
           "is skipped and dossiers still emit without identity_map rows."
       ),
   )
   ```

5. **NEW** `backend/app/utils/encryption.py` invariant: `_resolve_plaintext_email(sources) -> str | None` (lives in `person_dossier.py`) MUST return the first non-empty `value` from EMAIL findings, lowercased+stripped, **or** `None` if no EMAIL finding exists. The plaintext MUST flow directly into `encrypt_email()` and nowhere else — not into `logger`, not into `Finding.finding_metadata`, not into AI prompt payloads.

### Acceptance criteria

- **AC-020.1** — `hash_email("Jane@Example.com") == hash_email("jane@example.com")` (casing normalized).
- **AC-020.2** — `hash_email("a@b.c") == "f5b8a7c9e1d2..."` (deterministic — fixed test vector to catch regressions).
- **AC-020.3** — `encrypt_email("jane@example.com")` returns a string that starts with `gAAAAA` (Fernet token prefix) and is NOT equal to `"jane@example.com"`.
- **AC-020.4** — Given `PERSON_DOSSIER_ENCRYPTION_KEY` set to a valid Fernet key, `encrypt_email("x")` then `Fernet(key).decrypt(...)` round-trips to `"x"`.
- **AC-020.5** — Given `PERSON_DOSSIER_ENCRYPTION_KEY` unset (`None`), `encrypt_email("x")` raises `EncryptionKeyMissingError`.
- **AC-020.6** — Given the same `job_id` + `email_hash`, calling `_store_identity_map` twice produces exactly ONE row (DB UNIQUE constraint `uq_identity_map_job_hash` enforces idempotency; the second insert raises `IntegrityError` which is silently caught — the existing row wins).
- **AC-020.7** — `IdentityMap.encrypted_email` is a Fernet ciphertext — never the plaintext. Test: `test_encrypted_email_is_ciphertext_not_plaintext` (asserts `encrypted_email != "jane@example.com"`).
- **AC-020.8** — `IdentityMap.email_hash` is exactly 64 lowercase hex chars. Pydantic-style validator on the column OR a check constraint at insertion. (Pydantic-style: validate before insert.)

### Adversarial scenarios

- **A-020.a — Plaintext email leaks into logger**: a buggy `logger.info(...)` includes the email. Test: `test_no_plaintext_email_in_logs` (caplog-based). MUST FAIL if any log record contains `"jane@example.com"`.
- **A-020.b — Plaintext email in Finding.finding_metadata**: a buggy `_resolve_plaintext_email` that accidentally adds the email to the dumped dict. Test: `test_finding_metadata_has_no_plaintext_email` (assert `"email" not in finding_metadata` and `"plaintext_email" not in finding_metadata`).
- **A-020.c — Plaintext email in AI prompt**: `_assess_coherence` builds the user message from `dossier.model_dump()` which contains `email_hash` but NOT `email`. Test: `test_ai_prompt_payload_has_no_plaintext_email` (mock the LLM client and capture the user message).
- **A-020.d — Encryption key rotation**: changing `PERSON_DOSSIER_ENCRYPTION_KEY` to a new value renders existing `identity_map.encrypted_email` rows unreadable. Documented behavior per Open Question Q5 — single key v1, no rotation. Test: `test_encryption_key_rotation_breaks_existing_rows` (informational; not a regression test).
- **A-020.e — Fernet key invalid format**: `PERSON_DOSSIER_ENCRYPTION_KEY` set to `"not-a-valid-fernet-key"`. `encrypt_email("x")` raises `ValueError` (Fernet's constructor validates). `_store_identity_map` catches, logs warning, skips the row, dossier still emits.
- **A-020.f — `_resolve_plaintext_email` called on Finding without `value`**: defensive — returns `None`. (Pydantic min_length=1 at `base.py:32` SHOULD prevent this at construction.)
- **A-020.g — Empty EMAIL Finding list but other sources present**: no plaintext email available. `_resolve_plaintext_email` returns `None`. Dossier emits with `_no_pii` suffix in persona_id. No `identity_map` row. (Already covered by AC-016.3.)

### Privacy

- **SENSITIVE** — this REQ defines the privacy boundary. Three-layer verification per design.md §8:
  1. **Schema**: `PersonDossier` has no `email` field; `extra="forbid"`.
  2. **Code**: `_resolve_plaintext_email` → `encrypt_email` is the only path.
  3. **Storage**: Fernet ciphertext in `IdentityMap.encrypted_email`.

### Anti-block

- **Fernet encryption is O(1)** — bounded by 32-byte key + input size. For a typical email (~30 bytes), ciphertext = ~100 bytes. Per-dossier encryption is microseconds.
- **No subprocess, no network IO** — Fernet is pure Python stdlib (`from cryptography.fernet import Fernet`).

### Files affected

- **NEW** `backend/app/utils/encryption.py` (~90 lines)
- **NEW** `backend/tests/test_encryption.py` (~20 tests for round-trip, key errors, ciphertext format)
- **MODIFY** `backend/app/models.py` — add `IdentityMap` table class
- **MODIFY** `backend/app/config.py` — add `PERSON_DOSSIER_ENCRYPTION_KEY` setting
- **MODIFY** `.env.example` — document the new env var

---

## REQ-021: AI coherence assessment + bounded prompt

- **Priority**: P1 (graceful degradation if AI unavailable)
- **Type**: NEW PROMPT + NEW HELPER
- **Privacy classification**: **INTERNAL** (the AI sees only `email_hash` and synthetic metadata, never plaintext)

The system MUST add a system prompt `PROMPT_PERSON_DOSSIER` to
`backend/app/llm/prompts.py` and register it in the `PROMPTS` dict at line
293-308. The prompt MUST:

1. Define 4 coherence tags: `HIGH`, `MEDIUM`, `LOW`, `NONE`.
2. Bind to the existing `LDMValidationResult` schema (per `app/llm/schemas.py`).
3. Use a single verdict whose `value` = the email_hash.
4. Explicitly forbid the LLM from inferring or guessing the raw email.
5. Use `temperature=0.1` (matches the existing pattern at `base.py:162`).
6. Use `MAX_TOKENS=256` and `timeout=30s` via `asyncio.wait_for`.

The system MUST implement `_assess_coherence(dossier: PersonDossier) -> str | None`
in `person_dossier.py` that calls the existing `LLMClient.chat_completion`
once per dossier, parses the response into `LDMValidationResult`, extracts
the verdict string, and maps HIGH/MEDIUM/LOW/NONE to `dossier.coherence`.

### Acceptance criteria

- **AC-021.1** — `PROMPT_PERSON_DOSSIER` is a non-empty string that mentions all 4 coherence tags (HIGH, MEDIUM, LOW, NONE) and explicitly references the SHA-256 / `email_hash` invariant.
- **AC-021.2** — `PROMPTS["person_dossier"] == PROMPT_PERSON_DOSSIER` (registered in the dict at `prompts.py:293-308`).
- **AC-021.3** — `PersonDossierModule.get_ai_prompt()` returns `PROMPT_PERSON_DOSSIER`.
- **AC-021.4** — Given a valid `PersonDossier` (all 8 fields populated, `email_hash` = 64-char hex), `_assess_coherence` makes exactly ONE call to `LLMClient.chat_completion` (verified by mock spy).
- **AC-021.5** — Given the LLM returns a valid `LDMValidationResult` with `verdict="HIGH"`, `_assess_coherence` returns `"HIGH"`. Same for MEDIUM, LOW, NONE.
- **AC-021.6** — Given the LLM returns malformed JSON or raises `ValidationError`, `_assess_coherence` returns `None` (catches the exception, logs warning, does not raise).
- **AC-021.7** — Given the LLM call times out (`asyncio.wait_for` raises `TimeoutError` after 30s), `_assess_coherence` returns `None`.
- **AC-021.8** — Given stub mode (`MINIMAX_API_KEY=test-dummy`), `_assess_coherence` returns `None` (no AI call attempted — the existing `LLMClient` stub returns a CONTINUE verdict which has empty `verdicts[]`, so `_assess_coherence` cannot extract a tag and falls through to `None`).

### Adversarial scenarios

- **A-021.a — AI prompt payload contains plaintext email**: defensive test `test_ai_prompt_payload_has_no_plaintext_email`. If a future refactor accidentally dumps `dossier.email_hash`'s plaintext source into the user message, the test MUST FAIL.
- **A-021.b — AI suggests unauthorized action** (e.g. "use the email to log in"): the prompt explicitly forbids this in its "PRIVACY INVARIANTS" block. Tests verify the prompt string contains "NEVER" / "do NOT infer" / "Do NOT suggest outreach" substring assertions.
- **A-021.c — AI returns non-mappable verdict**: verdict = "MAYBE" (not in HIGH/MEDIUM/LOW/NONE). `_assess_coherence` MUST return `None` (defensive `.get` with default).
- **A-021.d — AI returns multiple verdicts** (one per finding in the payload): `_assess_coherence` MUST take the FIRST verdict (per design.md §7, "single verdict whose value is the email_hash").
- **A-021.e — LLMClient raises httpx.HTTPError**: `_assess_coherence` returns `None` (defensive `except Exception`).
- **A-021.f — Per-dossier cost ceiling**: total per-job tokens ≤ 1000 dossiers × 256 tokens = 256k tokens. Within standard MiniMax-M3 rate limits.

### Privacy

- **INTERNAL** — the LLM only sees `email_hash` (SHA-256 hex) and synthetic metadata (`profiles` list, `breach_exposures` summary, `role_relevance`). The prompt binds this with "PRIVACY INVARIANTS" — LLM is instructed never to guess the raw email.

### Anti-block

- **Bounded AI calls** — 1 call per dossier × 1000 dossier max = 1000 calls per job. At ~2s per call (typical), worst case ~33 minutes per job. Acceptable for Tier 3 batch recon.
- **Bounded token output** — `MAX_TOKENS=256` is enforced by `LLMClient.chat_completion` (parameter in the existing API).
- **Bounded time** — `asyncio.wait_for(llm.chat_completion(...), timeout=30.0)` per dossier. Total job wall-time bounded by `N × 30s` worst case.
- **No retry loop** — failures return `None` immediately, no exponential backoff in `_assess_coherence` (LLMClient may have its own retry policy at the transport level — out of scope here).

### Files affected

- **MODIFY** `backend/app/llm/prompts.py` — add `PROMPT_PERSON_DOSSIER` constant + `PROMPTS["person_dossier"] = PROMPT_PERSON_DOSSIER` entry
- **NEW** `backend/app/modules/person_dossier.py` — `get_ai_prompt()`, `_assess_coherence(dossier)` helper
- **NEW** `backend/tests/test_person_dossier.py` — AI prompt substring assertions + coherence mapping tests

---

## Non-functional requirements

- **NFR-1**: `person_dossier.py` line coverage ≥ 90% (`pytest --cov-fail-under=90`). Verified by `pytest --cov=app.modules.person_dossier backend/tests/test_person_dossier.py`.
- **NFR-2**: `encryption.py` line coverage ≥ 95% (critical for privacy — NFR-2 stricter than NFR-1). Verified by `pytest --cov=app.utils.encryption backend/tests/test_encryption.py`.
- **NFR-3**: AI prompt returns deterministic, parseable JSON output. `LDMValidationResult.model_validate(response)` MUST succeed for valid LLM responses. Verified by replaying the prompt against a recorded fixture.
- **NFR-4**: NO raw email in logs, handoff exports, AI prompt payloads, or `Finding.finding_metadata`. Verified by a series of caplog + payload-capture tests in `test_person_dossier.py`.
- **NFR-5**: All five new/modified files MUST pass `ruff check` and `ruff format --check` (per project pre-commit hook). Apache-2.0 license header on every new `.py` file (per project rule — note: this spec.md is NOT a Python file, no header needed).
- **NFR-6**: Total wall-clock per `person_dossier.run()` for 1000 dossiers ≤ 10 minutes (10 dossiers/sec). LLM calls dominate. Test: `test_run_wall_clock_within_budget` (mock LLM at ~50ms per call).
- **NFR-7**: `IdentityMap` table MUST be created by `Base.metadata.create_all` on startup (no separate Alembic migration needed in v0.1.x — consistent with how the RoE tables were added in PR 1 commits `6d43ee4` and `7f198fb` per the design.md precedent at `wiki/sesiones/.../2026-10-07-plan-mejoras-person-osint.md`).

---

## Open questions (carried from design.md §12 + new ones)

| Q | Question | Recommendation / Status |
|---|---|---|
| **Q1** | Dependency wiring for `person_dossier` vs. its 3 SOURCE_MODULES in `job_runner.py` — additive `depends_on` attribute (touch 14 modules + tests) vs. localized `ModuleStatus.SKIPPED` polling? | **DEFERRED to implementation.** Recommend **(b)** — `person_dossier.run()` polls sibling `ModuleRun.status` and returns `ModuleStatus.SKIPPED` if any sibling is still RUNNING. Localized, no risk to existing modules. **Implementation must choose (a) or (b) and document in the module docstring.** |
| **Q2** | Breach orphan policy — drop unmatched CREDENTIAL_EXPOSURE to `errors`, OR emit a DOSSIER per breach even without identity? | **DEFERRED to implementation.** Recommend **(errors)** — v1 default per design.md §12. Breach-only dossiers are a follow-up. Already reflected in AC-017.5. |
| **Q3** | Persona counter scope — per-job or per-organization-across-jobs? | **DEFERRED to implementation.** Recommend **(per-job)** — counter resets each `job_id`. Cross-job stability requires schema change to key IdentityMap by `(target, email_hash)`. v1 per-job. |
| **Q4** | Coherence model — per-dossier AI call (N calls) vs. batched one-call (1 call for all)? | **DEFERRED to implementation.** Recommend **(per-dossier)** — better per-dossier accuracy. Batching is a follow-up if token cost becomes a problem. Per-dossier already implemented per AC-021.4. |
| **Q5** | Encryption key rotation — single key v1 vs. multi-key support? | **DEFERRED to implementation.** Recommend **(single key v1)**. Fernet does not support rotation natively. Document this in `.env.example`. Multi-key is a follow-up. |
| **Q6** | `frontend/src/components/ModuleCatalog.tsx` does NOT exist in this codebase (verified — only `ModuleCard.tsx` is at `frontend/src/components/`). The design.md §11 says MODIFY `ModuleCatalog.tsx`. | **DEFERRED to implementation.** Recommend **creating** `frontend/src/components/ModuleCatalog.tsx` (a new catalog view that lists all modules, of which ModuleCard renders one row), OR adding the `person_dossier` entry directly to `ModuleCard.tsx` if a catalog view is out of scope. Implementation must confirm the integration point before merging. |

---

## Acceptance test inventory (mapped to REQs)

Per design.md §11, the implementation MUST include `27 tests` in
`backend/tests/test_person_dossier.py` and `~20 tests` in
`backend/tests/test_encryption.py`. This spec does NOT enumerate the test list
(TDD: tests are written AFTER the REQs and driven by the ACs above). Test
authors MUST cover every AC-xxx.x and every A-xxx.x adversarial scenario.

Recommended test groupings (informational, not normative):

| Test file | Group | # tests (approx.) |
|---|---|---|
| `test_person_dossier.py` | Schema (`PersonDossier`, `FindingType.DOSSIER`) | 4 |
| `test_person_dossier.py` | `_extract_email_hash` happy + adversarial paths | 8 |
| `test_person_dossier.py` | `_compute_confidence` cases (REQ-019 ACs) | 6 |
| `test_person_dossier.py` | `run()` integration (siblings complete / failed / partial) | 4 |
| `test_person_dossier.py` | AI prompt + `_assess_coherence` (REQ-021 ACs + A-021.x) | 5 |
| `test_encryption.py` | `hash_email` + `encrypt_email` round-trip + key errors | ~10 |
| `test_encryption.py` | Privacy invariants (no plaintext in logs / metadata / AI payload) | ~10 |

---

## Cross-references

- **Design**: `openspec/changes/2026-10-12-pr4-person-dossier/design.md` (authoritative)
- **Plan**: `wiki/sesiones/2026-10-07-plan-mejoras-person-osint.md` (PR 4 section)
- **RoE precedent** (PR 1 — already merged): `openspec/changes/2026-10-12-pr1-roe/design.md`
- **Module contract**: `backend/app/modules/base.py` (Finding, FindingType, BaseReconModule)
- **FindingType enum**: `backend/app/models.py:66-83`
- **Prompt registry**: `backend/app/llm/prompts.py:293-308`
- **Handoff schema**: `backend/app/handoff/schema.py` (public contract — unchanged by PR 4; handoff consumes DOSSIER findings via the existing `Finding.value` + `finding_metadata` shape)
- **Module registry**: `backend/app/modules/__init__.py:35-55`

---

*End of spec — PR 4 person_dossier aggregator.*