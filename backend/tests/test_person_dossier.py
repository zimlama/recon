# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PersonDossier Pydantic schema (PR 4 — person_dossier aggregator).

Per spec.md REQ-018:
  - PersonDossier: 8-field BaseModel with extra='forbid'
  - email_hash: SHA-256 hex pseudonym
  - profiles: list[str] (SOCIAL_PROFILE URLs)
  - breach_exposures: list[dict]
  - role_relevance: Literal["HIGH","MEDIUM","LOW"]
  - priority_for_targeting: Literal["HIGH","MEDIUM","LOW"]
  - source_modules: list[str]
  - confidence: float (boosted, capped at 1.0)
  - coherence: str | None (AI-assessed, populated post-validation)
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.modules.base import Finding
from app.modules.person_dossier import (
    PersonDossier,
    _aggregate_confidence,
    _extract_email_hash,
    _group_by_email_hash,
    _resolve_plaintext_email,
)
from app.modules.person_dossier import hash_email as _hash_email  # noqa: F401
from app.models import FindingType


def _valid_payload() -> dict:
    """Minimal valid PersonDossier payload for tests."""
    return {
        "email_hash": "a" * 64,
        "profiles": ["https://linkedin.com/in/jane"],
        "breach_exposures": [{"email_hash_prefix": "abc1234567", "breach_count": 3}],
        "role_relevance": "HIGH",
        "priority_for_targeting": "HIGH",
        "source_modules": ["employee_osint", "socmint"],
        "confidence": 0.9,
        "coherence": "HIGH",
    }


# ---- Happy path ----


def test_person_dossier_accepts_valid_payload() -> None:
    """PersonDossier accepts all 8 documented fields."""
    pd = PersonDossier(**_valid_payload())
    assert pd.email_hash == "a" * 64
    assert pd.profiles == ["https://linkedin.com/in/jane"]
    assert pd.role_relevance == "HIGH"
    assert pd.priority_for_targeting == "HIGH"
    assert pd.source_modules == ["employee_osint", "socmint"]
    assert pd.confidence == 0.9
    assert pd.coherence == "HIGH"


def test_person_dossier_round_trip_model_dump() -> None:
    """PersonDossier.model_dump() returns a dict with all 8 fields."""
    pd = PersonDossier(**_valid_payload())
    d = pd.model_dump()
    expected_keys = {
        "email_hash", "profiles", "breach_exposures",
        "role_relevance", "priority_for_targeting",
        "source_modules", "confidence", "coherence",
    }
    assert set(d.keys()) == expected_keys


def test_person_dossier_coherence_defaults_to_none() -> None:
    """coherence defaults to None when omitted (populated post-AI-validation)."""
    payload = _valid_payload()
    payload.pop("coherence")
    pd = PersonDossier(**payload)
    assert pd.coherence is None


def test_person_dossier_empty_profiles_allowed() -> None:
    """profiles defaults to empty list when omitted."""
    payload = _valid_payload()
    payload.pop("profiles")
    pd = PersonDossier(**payload)
    assert pd.profiles == []


def test_person_dossier_empty_breach_exposures_allowed() -> None:
    """breach_exposures defaults to empty list when omitted."""
    payload = _valid_payload()
    payload.pop("breach_exposures")
    pd = PersonDossier(**payload)
    assert pd.breach_exposures == []


# ---- extra="forbid" ----


def test_person_dossier_rejects_unknown_field() -> None:
    """extra='forbid' prevents accidental schema additions.

    Per spec.md AC-018.2 — protects the privacy boundary.
    """
    payload = _valid_payload()
    payload["forbidden_field"] = "leak"
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


def test_person_dossier_rejects_plaintext_email_field() -> None:
    """`email` is explicitly forbidden — REQ-018 privacy invariant.

    This is the schema-layer privacy guarantee: there's no way to attach
    a plaintext `email` field even by accident.
    """
    payload = _valid_payload()
    payload["email"] = "jane@example.com"
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


# ---- Literal type enforcement ----


def test_person_dossier_role_relevance_rejects_invalid_value() -> None:
    """role_relevance MUST be HIGH / MEDIUM / LOW (per AC-018.5)."""
    payload = _valid_payload()
    payload["role_relevance"] = "MAYBE"
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


def test_person_dossier_priority_rejects_invalid_value() -> None:
    """priority_for_targeting MUST be HIGH / MEDIUM / LOW (per AC-018.5)."""
    payload = _valid_payload()
    payload["priority_for_targeting"] = "URGENT"
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


@pytest.mark.parametrize("value", ["HIGH", "MEDIUM", "LOW"])
def test_person_dossier_role_relevance_accepts_all_literals(value: str) -> None:
    """role_relevance accepts each valid literal."""
    payload = _valid_payload()
    payload["role_relevance"] = value
    pd = PersonDossier(**payload)
    assert pd.role_relevance == value


# ---- Confidence bounds ----


def test_person_dossier_confidence_rejects_above_one() -> None:
    """confidence > 1.0 MUST raise ValidationError (per A-018.c)."""
    payload = _valid_payload()
    payload["confidence"] = 1.5
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


def test_person_dossier_confidence_rejects_negative() -> None:
    """confidence < 0.0 MUST raise ValidationError."""
    payload = _valid_payload()
    payload["confidence"] = -0.1
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


# ---- email_hash format ----


def test_person_dossier_email_hash_rejects_non_64_char() -> None:
    """email_hash MUST be 64 hex chars (per A-018.d)."""
    payload = _valid_payload()
    payload["email_hash"] = "abc123"  # too short
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


def test_person_dossier_email_hash_rejects_non_hex() -> None:
    """email_hash MUST be lowercase hex (per A-018.d)."""
    payload = _valid_payload()
    payload["email_hash"] = "Z" * 64  # uppercase / non-hex
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


def test_person_dossier_email_hash_rejects_bytes() -> None:
    """email_hash MUST be a str (not bytes)."""
    payload = _valid_payload()
    payload["email_hash"] = b"a" * 64
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


# ---- Source modules list ----


def test_person_dossier_source_modules_accepts_any_list_of_strings() -> None:
    """source_modules is a list of module-name strings."""
    payload = _valid_payload()
    payload["source_modules"] = ["employee_osint", "socmint", "breach_data"]
    pd = PersonDossier(**payload)
    assert pd.source_modules == ["employee_osint", "socmint", "breach_data"]


def test_person_dossier_source_modules_defaults_empty() -> None:
    """source_modules defaults to [] when omitted."""
    payload = _valid_payload()
    payload.pop("source_modules")
    pd = PersonDossier(**payload)
    assert pd.source_modules == []


# ---- Coherence values ----


@pytest.mark.parametrize("value", ["HIGH", "MEDIUM", "LOW", "NONE"])
def test_person_dossier_coherence_accepts_valid_tags(value: str) -> None:
    """coherence accepts the 4 AI-defined tags (HIGH/MEDIUM/LOW/NONE)."""
    payload = _valid_payload()
    payload["coherence"] = value
    pd = PersonDossier(**payload)
    assert pd.coherence == value


def test_person_dossier_coherence_rejects_other_string() -> None:
    """coherence rejects anything not in HIGH/MEDIUM/LOW/NONE/None."""
    payload = _valid_payload()
    payload["coherence"] = "MAYBE"
    with pytest.raises(ValidationError):
        PersonDossier(**payload)


# ---------------------------------------------------------------------------
# _extract_email_hash — REQ-017 AC-017.1, AC-017.2, AC-017.3, AC-017.6
# ---------------------------------------------------------------------------


def _email_finding(value: str, conf: float = 0.9, meta: dict | None = None) -> Finding:
    return Finding(
        type=FindingType.EMAIL,
        value=value,
        source="email_harvesting",
        confidence=conf,
        finding_metadata=meta if meta is not None else {},
    )


def _username_finding(email_hash: str | None = None, conf: float = 0.7) -> Finding:
    meta = {"email_hash": email_hash} if email_hash is not None else {}
    return Finding(
        type=FindingType.USERNAME,
        value="jdoe",
        source="employee_osint",
        confidence=conf,
        finding_metadata=meta,
    )


def _social_profile_finding(email_hash: str | None = None) -> Finding:
    meta = {"email_hash": email_hash} if email_hash is not None else {}
    return Finding(
        type=FindingType.SOCIAL_PROFILE,
        value="https://linkedin.com/in/jane",
        source="socmint",
        confidence=0.7,
        finding_metadata=meta,
    )


def _credential_exposure_finding(prefix: str = "abc1234567", domain: str = "example.com") -> Finding:
    return Finding(
        type=FindingType.CREDENTIAL_EXPOSURE,
        value=f"3_breaches_for_{prefix}",
        source="hibp_kanon",
        confidence=1.0,
        finding_metadata={"email_hash_prefix": prefix, "domain": domain, "breach_count": 3},
    )


def test_extract_email_hash_from_email_finding_lowercases() -> None:
    """EMAIL finding's value is lowercased + stripped before hashing.

    Per AC-017.1 — 'Jane@Example.com' and 'jane@example.com' produce the same hash.
    """
    import hashlib

    expected = hashlib.sha256("jane@example.com".encode("utf-8")).hexdigest()
    assert _extract_email_hash(_email_finding("Jane@Example.com")) == expected


def test_extract_email_hash_normalizes_casing() -> None:
    """Casing is normalized — same email different cases → same hash.

    Per AC-017.2.
    """
    h1 = _extract_email_hash(_email_finding("ja@example.com"))
    h2 = _extract_email_hash(_email_finding("JA@EXAMPLE.COM"))
    assert h1 == h2


def test_extract_email_hash_from_metadata_64_hex() -> None:
    """USERNAME finding with 64-hex metadata returns that hash.

    Per AC-017.3.
    """
    h = "f" * 64
    assert _extract_email_hash(_username_finding(email_hash=h)) == h


def test_extract_email_hash_from_metadata_64_hex_short_rejected() -> None:
    """USERNAME finding with non-64-char metadata returns None (per AC-017.3)."""
    assert _extract_email_hash(_username_finding(email_hash="abc")) is None


def test_extract_email_hash_from_metadata_non_hex_rejected() -> None:
    """USERNAME finding with non-hex 64-char metadata returns None."""
    assert _extract_email_hash(_username_finding(email_hash="Z" * 64)) is None


def test_extract_email_hash_from_credential_exposure_returns_none() -> None:
    """CREDENTIAL_EXPOSURE never returns a per-email hash — domain join only.

    Per spec.md REQ-017 — its 10-char SHA-1 prefix fails the 64-char check.
    """
    assert _extract_email_hash(_credential_exposure_finding()) is None


def test_extract_email_hash_from_social_profile_with_metadata() -> None:
    """SOCIAL_PROFILE finding with 64-char metadata returns that hash."""
    h = "a" * 64
    assert _extract_email_hash(_social_profile_finding(email_hash=h)) == h


def test_extract_email_hash_from_social_profile_without_metadata() -> None:
    """SOCIAL_PROFILE finding without metadata returns None."""
    assert _extract_email_hash(_social_profile_finding()) is None


def test_extract_email_hash_empty_value_returns_none() -> None:
    """Empty EMAIL value returns None (per A-017.a).

    We bypass Pydantic's min_length=1 via ``model_construct`` to simulate
    a corrupt Finding row that bypassed validation (defensive — per the
    Pydantic constraint, this shouldn't happen, but the helper must still
    not crash).
    """
    corrupt = Finding.model_construct(
        type=FindingType.EMAIL,
        value="",
        source="email_harvesting",
        confidence=0.9,
        finding_metadata={},
    )
    assert _extract_email_hash(corrupt) is None


def test_extract_email_hash_missing_metadata_returns_none() -> None:
    """USERNAME with no 'email_hash' key returns None (per A-017.c)."""
    f = Finding(
        type=FindingType.USERNAME,
        value="jdoe",
        source="employee_osint",
        confidence=0.7,
        finding_metadata={"platform_url": "https://linkedin.com/in/jdoe"},
    )
    assert _extract_email_hash(f) is None


def test_extract_email_hash_metadata_is_none_returns_none() -> None:
    """USERNAME with finding_metadata=None returns None (per A-017.d).

    Same defensive scenario — use ``model_construct`` to bypass the
    Pydantic default_factory=dict so we can test the helper's resilience
    to malformed DB rows.
    """
    corrupt = Finding.model_construct(
        type=FindingType.USERNAME,
        value="jdoe",
        source="employee_osint",
        confidence=0.7,
        finding_metadata=None,
    )
    assert _extract_email_hash(corrupt) is None


def test_extract_email_hash_other_types_return_none() -> None:
    """Non-EMAIL/USERNAME/SOCIAL_PROFILE findings return None (per AC-017.6)."""
    f = Finding(
        type=FindingType.SUBDOMAIN,
        value="api.example.com",
        source="subfinder",
        confidence=0.9,
        finding_metadata={},
    )
    assert _extract_email_hash(f) is None


# ---------------------------------------------------------------------------
# _group_by_email_hash — REQ-017 grouping
# ---------------------------------------------------------------------------


def test_group_by_email_hash_groups_same_email() -> None:
    """Multiple findings for the same email land in one bucket."""
    import hashlib

    expected = hashlib.sha256("jane@example.com".encode("utf-8")).hexdigest()
    f1 = _email_finding("jane@example.com")
    f2 = _username_finding(email_hash=expected)
    bucket = _group_by_email_hash([("email_harvesting", f1), ("employee_osint", f2)], set())
    assert expected in bucket
    assert len(bucket[expected]) == 2


def test_group_by_email_hash_separates_distinct_emails() -> None:
    """Two different emails → two buckets."""
    f1 = _email_finding("alice@example.com")
    f2 = _email_finding("bob@example.com")
    bucket = _group_by_email_hash([("email_harvesting", f1), ("email_harvesting", f2)], set())
    assert len(bucket) == 2


def test_group_by_email_hash_drops_no_hash_findings() -> None:
    """Findings with no email_hash (e.g. CREDENTIAL_EXPOSURE) are dropped from bucketing."""
    f_email = _email_finding("jane@example.com")
    f_breach = _credential_exposure_finding()
    bucket = _group_by_email_hash([("email_harvesting", f_email), ("breach_data", f_breach)], set())
    assert len(bucket) == 1


def test_group_by_email_hash_skips_already_dossiered() -> None:
    """email_hashes already in `already_dossiered` are dropped (idempotency)."""
    import hashlib

    h = hashlib.sha256("jane@example.com".encode("utf-8")).hexdigest()
    f = _email_finding("jane@example.com")
    bucket = _group_by_email_hash([("email_harvesting", f)], {h})
    assert bucket == {}


def test_group_by_email_hash_empty_input() -> None:
    """Empty input → empty bucket."""
    assert _group_by_email_hash([], set()) == {}


# ---------------------------------------------------------------------------
# _aggregate_confidence — REQ-019 AC-019.1..6
# ---------------------------------------------------------------------------


def test_aggregate_confidence_two_sources_boosts() -> None:
    """2 sources: max + 0.1 (per AC-019.1)."""
    findings = [
        _email_finding("a@example.com", conf=0.6),
        _email_finding("a@example.com", conf=0.8),
    ]
    assert _aggregate_confidence(findings) == pytest.approx(0.9)


def test_aggregate_confidence_one_source_no_boost() -> None:
    """1 source: just the source confidence (per AC-019.2)."""
    findings = [_email_finding("a@example.com", conf=0.6)]
    assert _aggregate_confidence(findings) == pytest.approx(0.6)


def test_aggregate_confidence_caps_at_one() -> None:
    """2 sources with max=1.0 still capped at 1.0 (per AC-019.3)."""
    findings = [
        _email_finding("a@example.com", conf=0.95),
        _email_finding("a@example.com", conf=1.0),
    ]
    assert _aggregate_confidence(findings) == pytest.approx(1.0)


def test_aggregate_confidence_three_sources_no_extra_boost() -> None:
    """3 sources: still max + 0.1 (per AC-019.4)."""
    findings = [
        _email_finding("a@example.com", conf=0.5),
        _email_finding("a@example.com", conf=0.7),
        _email_finding("a@example.com", conf=0.9),
    ]
    assert _aggregate_confidence(findings) == pytest.approx(1.0)


def test_aggregate_confidence_three_sources_all_at_ceiling() -> None:
    """3 sources at 1.0 → still 1.0 (per AC-019.5)."""
    findings = [
        _email_finding("a@example.com", conf=1.0),
        _email_finding("a@example.com", conf=1.0),
        _email_finding("a@example.com", conf=1.0),
    ]
    assert _aggregate_confidence(findings) == pytest.approx(1.0)


def test_aggregate_confidence_empty_returns_zero() -> None:
    """Empty list returns 0.0 (per AC-019.6)."""
    assert _aggregate_confidence([]) == 0.0


# ---------------------------------------------------------------------------
# _resolve_plaintext_email — privacy boundary
# ---------------------------------------------------------------------------


def test_resolve_plaintext_email_returns_first_email_lowercased() -> None:
    """Returns the first EMAIL finding's value, lowercased + stripped."""
    f1 = _username_finding(email_hash="a" * 64)
    f2 = _email_finding("  Jane@Example.com ")
    f3 = _social_profile_finding(email_hash="b" * 64)
    assert _resolve_plaintext_email([f1, f2, f3]) == "jane@example.com"


def test_resolve_plaintext_email_returns_none_when_no_email() -> None:
    """No EMAIL finding → None."""
    findings = [
        _username_finding(email_hash="a" * 64),
        _credential_exposure_finding(),
    ]
    assert _resolve_plaintext_email(findings) is None


def test_resolve_plaintext_email_returns_none_for_empty_value() -> None:
    """EMAIL finding with empty value → skipped, returns None if no other EMAIL."""
    corrupt = Finding.model_construct(
        type=FindingType.EMAIL,
        value="",
        source="email_harvesting",
        confidence=0.9,
        finding_metadata={},
    )
    assert _resolve_plaintext_email([corrupt]) is None


# ---------------------------------------------------------------------------
# PersonDossierModule.run() — orchestrator integration
# ---------------------------------------------------------------------------

import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.database import Base, SessionLocal, engine
from app.models import (
    Finding as FindingModel,
    IdentityMap,
    Job,
    JobStatus,
    ModuleRun,
    ModuleStatus,
    ModuleTier,
)
from app.modules.base import ModuleInput
from app.modules.person_dossier import PersonDossierModule


@pytest.fixture
def fresh_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator:
    """In-memory SQLite session with a fresh schema per test."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/dossier.db")
    monkeypatch.setenv("PERSON_DOSSIER_ENCRYPTION_KEY", "")
    from app.config import get_settings

    get_settings.cache_clear()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def mock_llm(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Patch PersonDossierModule._make_llm_client to return a mock.

    The default conftest MINIMAX_API_KEY is `test-dummy-key`, which makes
    the real LLMClient try (and fail) to reach localhost:9999 — adding
    30+ seconds to every run() test. This fixture swaps in a fast-returning
    AsyncMock so each LLM call resolves immediately with empty verdicts
    (the same shape the LLMClient's stub returns).
    """
    mock = AsyncMock()
    mock.chat_completion = AsyncMock(
        return_value={
            "verdicts": [],
            "summary": "stub",
            "recommended_action": "CONTINUE",
            "recommended_next_module_chain": [],
        }
    )
    mock.close = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "app.modules.person_dossier.PersonDossierModule._make_llm_client",
        staticmethod(lambda: mock),
    )
    return mock


def _seed_job_with_module_runs(
    db,
    job_id: str = "test-job-1",
    target: str = "example.com",
    modules: list[tuple[str, ModuleStatus, ModuleTier]] | None = None,
) -> Job:
    """Create a Job + ModuleRun rows for the given modules (defaults to all siblings COMPLETED)."""
    if modules is None:
        modules = [
            ("employee_osint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
            ("socmint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
            ("breach_data", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
        ]
    job = Job(
        id=job_id,
        target=target,
        selected_modules=[m[0] for m in modules],
        status=JobStatus.VALIDATING,
    )
    db.add(job)
    for module_name, status, tier in modules:
        db.add(
            ModuleRun(
                job_id=job_id,
                module_name=module_name,
                module_tier=tier,
                status=status,
                started_at=job.created_at,
                completed_at=job.created_at,
            )
        )
    db.commit()
    db.refresh(job)
    return job


def _seed_finding(
    db,
    job_id: str,
    module_name: str,
    finding_type: FindingType,
    value: str,
    confidence: float = 0.8,
    finding_metadata: dict | None = None,
) -> FindingModel:
    """Insert a Finding row attached to the (job_id, module_name) ModuleRun."""
    module_run = (
        db.query(ModuleRun)
        .filter(ModuleRun.job_id == job_id, ModuleRun.module_name == module_name)
        .first()
    )
    assert module_run is not None, f"ModuleRun {module_name} not seeded"
    row = FindingModel(
        module_run_id=module_run.id,
        type=finding_type,
        value=value,
        source=module_name,
        confidence=confidence,
        finding_metadata=finding_metadata or {},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@pytest.mark.asyncio
async def test_run_no_sibling_runs_returns_empty(fresh_db, mock_llm) -> None:
    """AC-016.5: no completed sibling modules → empty ModuleOutput.

    We seed only the Job + ModuleRun rows but NO findings, so the sibling
    query returns 0 rows. Expect: findings=[], errors=['no completed sibling modules'].
    """
    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(db)
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert output.findings == []
    assert "no completed sibling modules" in output.errors


@pytest.mark.asyncio
async def test_run_one_source_emits_dossier_with_source_confidence(fresh_db, mock_llm) -> None:
    """AC-016.6: single source → confidence = source conf (no boost).

    To exercise the single-source branch we need an EMAIL finding (otherwise
    CREDENTIAL_EXPOSURE alone is bucketed as an orphan). We seed a single
    EMAIL from email_harvesting (only that module is COMPLETED) so the
    bucket has exactly one source.
    """
    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="solo@example.com",
            confidence=0.85,
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    f = output.findings[0]
    assert f.type == FindingType.DOSSIER
    assert f.value.startswith("Persona_")
    assert f.confidence == 0.85
    assert f.finding_metadata["source_modules"] == ["email_harvesting"]


@pytest.mark.asyncio
async def test_run_two_email_sources_aggregate_same_identity(fresh_db, mock_llm) -> None:
    """AC-016.1: two EMAIL findings for the same email → 1 dossier, source_modules includes email_harvesting + employee_osint."""
    module = PersonDossierModule()
    with SessionLocal() as db:
        # Run email_harvesting AND employee_osint with EMAIL findings for same identity.
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
                ("employee_osint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
                ("socmint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
                ("breach_data", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="jane@example.com",
            confidence=0.85,
        )
        # employee_osint can also produce EMAIL findings in practice.
        _seed_finding(
            db,
            "test-job-1",
            "employee_osint",
            FindingType.EMAIL,
            value="jane@example.com",
            confidence=0.7,
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    f = output.findings[0]
    assert f.type == FindingType.DOSSIER
    # 2 sources → confidence = max(0.85, 0.7) + 0.1 = 0.95
    assert f.confidence == pytest.approx(0.95)
    assert set(f.finding_metadata["source_modules"]) == {"email_harvesting", "employee_osint"}


@pytest.mark.asyncio
async def test_run_no_email_in_bucket_emits_no_pii_persona(fresh_db, mock_llm) -> None:
    """AC-016.3: a USERNAME/SOCIAL_PROFILE finding with no EMAIL sibling
    (and no email_harvesting run) → persona_id ends with '_no_pii',
    no identity_map row.

    We seed a USERNAME finding (which buckets via metadata.email_hash)
    but no EMAIL setting the encryption key, so the identity_map row
    is skipped but the dossier is still emitted.
    """
    module = PersonDossierModule()
    import hashlib

    h = hashlib.sha256("jane@example.com".encode("utf-8")).hexdigest()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("employee_osint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "employee_osint",
            FindingType.USERNAME,
            value="jdoe",
            confidence=0.7,
            finding_metadata={"email_hash": h},
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    assert output.findings[0].value.endswith("_no_pii")
    # Verify no identity_map row.
    with SessionLocal() as db:
        rows = db.query(IdentityMap).all()
        assert rows == []


@pytest.mark.asyncio
async def test_run_writes_identity_map_with_ciphertext(fresh_db, monkeypatch, mock_llm) -> None:
    """AC-016.2: EMAIL finding → IdentityMap row with Fernet ciphertext (not plaintext)."""
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PERSON_DOSSIER_ENCRYPTION_KEY", key)
    from app.config import get_settings

    get_settings.cache_clear()

    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="jane@example.com",
            confidence=0.85,
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    # Verify the IdentityMap row exists with ciphertext (not plaintext).
    with SessionLocal() as db:
        rows = db.query(IdentityMap).all()
        assert len(rows) == 1
        row = rows[0]
        assert "jane@example.com" not in row.encrypted_email  # AC-020.7
        assert row.encrypted_email.startswith("gAAAAA")
        # Round-trip: Fernet can decrypt back to the plaintext.
        assert Fernet(key.encode("ascii")).decrypt(row.encrypted_email.encode("ascii")).decode() == "jane@example.com"


@pytest.mark.asyncio
async def test_run_idempotent_no_duplicate_dossiers(fresh_db, monkeypatch, mock_llm) -> None:
    """AC-016.4: re-running on the same job_id produces zero additional DOSSIER findings."""
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PERSON_DOSSIER_ENCRYPTION_KEY", key)
    from app.config import get_settings

    get_settings.cache_clear()

    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="jane@example.com",
            confidence=0.85,
        )

    # First run: 1 DOSSIER
    out1 = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(out1.findings) == 1

    # Second run: 0 additional DOSSIER (idempotency)
    out2 = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(out2.findings) == 0


@pytest.mark.asyncio
async def test_run_skips_when_sibling_still_running(fresh_db, mock_llm) -> None:
    """AC-016.A: a sibling ModuleRun in RUNNING status → person_dossier returns SKIPPED."""
    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("employee_osint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
                ("socmint", ModuleStatus.RUNNING, ModuleTier.TIER_3),  # still running
                ("breach_data", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
            ],
        )
        # Add a finding for the COMPLETED siblings so we don't get the
        # "no completed sibling modules" path.
        _seed_finding(
            db,
            "test-job-1",
            "employee_osint",
            FindingType.EMAIL,
            value="jane@example.com",
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    # Sibling still running → dossier skipped.
    assert output.findings == []
    assert any("sibling still running" in e for e in output.errors)


@pytest.mark.asyncio
async def test_run_missing_job_raises(fresh_db, mock_llm) -> None:
    """A-016.e: non-existent job_id raises ValueError."""
    module = PersonDossierModule()
    with pytest.raises(ValueError, match="job not found"):
        await module.run(ModuleInput(target="example.com", job_id="nonexistent-job"))


@pytest.mark.asyncio
async def test_run_no_plaintext_in_logs(fresh_db, monkeypatch, caplog, mock_llm) -> None:
    """A-020.a: no log line contains the plaintext email.

    We register a key so the encryption path runs, then assert no log
    record contains the plaintext.
    """
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PERSON_DOSSIER_ENCRYPTION_KEY", key)
    from app.config import get_settings

    get_settings.cache_clear()

    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="leaky@example.com",
            confidence=0.85,
        )

    import logging

    caplog.set_level(logging.DEBUG)
    await module.run(ModuleInput(target="example.com", job_id="test-job-1"))

    plaintext = "leaky@example.com"
    for record in caplog.records:
        assert plaintext not in record.getMessage(), (
            f"Plaintext email leaked to logs: {record.getMessage()!r}"
        )


@pytest.mark.asyncio
async def test_run_finding_metadata_has_no_plaintext_email(fresh_db, monkeypatch, mock_llm) -> None:
    """A-020.b: Finding.finding_metadata contains no plaintext email."""
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PERSON_DOSSIER_ENCRYPTION_KEY", key)
    from app.config import get_settings

    get_settings.cache_clear()

    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="private@example.com",
            confidence=0.85,
        )

    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    meta = output.findings[0].finding_metadata
    assert "email" not in meta
    assert "plaintext_email" not in meta


@pytest.mark.asyncio
async def test_run_no_breach_orphans_in_findings(fresh_db, mock_llm) -> None:
    """Orphan breach (CREDENTIAL_EXPOSURE with no matching EMAIL) surfaces in errors."""
    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(db)
        _seed_finding(
            db,
            "test-job-1",
            "breach_data",
            FindingType.CREDENTIAL_EXPOSURE,
            value="3_breaches_for_orphan01",
            finding_metadata={
                "email_hash_prefix": "orphan01",
                "domain": "nowhere.com",  # no EMAIL for this domain
                "breach_count": 3,
            },
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert output.findings == []
    assert any("orphan breach" in e for e in output.errors)


@pytest.mark.asyncio
async def test_run_breach_domain_join_attaches_to_dossier(fresh_db, mock_llm) -> None:
    """CREDENTIAL_EXPOSURE whose domain matches an EMAIL finding joins the dossier."""
    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
                ("breach_data", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="jane@example.com",
            confidence=0.85,
        )
        _seed_finding(
            db,
            "test-job-1",
            "breach_data",
            FindingType.CREDENTIAL_EXPOSURE,
            value="3_breaches_for_abc123",
            finding_metadata={
                "email_hash_prefix": "abc1234567",
                "domain": "example.com",
                "breach_count": 3,
            },
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    meta = output.findings[0].finding_metadata
    assert "breach_data" in meta["source_modules"]
    assert len(meta["breach_exposures"]) == 1


@pytest.mark.asyncio
async def test_run_module_metadata_consistent(fresh_db, mock_llm) -> None:
    """Module metadata is correct (tier, consent, etc.) — runs after a basic execution."""
    module = PersonDossierModule()
    assert module.name == "person_dossier"
    assert module.tier.value == "tier_3"
    assert module.requires_consent is True
    assert module.requires_api_keys == []
    assert len(module.mitre_techniques) > 0
    assert isinstance(module.get_ai_prompt(), str)
    assert len(module.get_ai_prompt()) > 100
    assert "HIGH" in module.get_ai_prompt()
    assert "MEDIUM" in module.get_ai_prompt()
    assert "LOW" in module.get_ai_prompt()
    assert "NONE" in module.get_ai_prompt()
    assert "SHA-256" in module.get_ai_prompt() or "email_hash" in module.get_ai_prompt()
    assert "NEVER" in module.get_ai_prompt()  # privacy invariant


# ---- Coverage / branch tests ----


def test_domain_of_email_no_at_sign() -> None:
    """`_domain_of_email` returns empty string when input has no '@'.

    Defensive branch (line 201) — should never be hit in practice but
    keeps the helper robust against garbage input.
    """
    from app.modules.person_dossier import _domain_of_email

    assert _domain_of_email("no-at-sign-string") == ""
    assert _domain_of_email("") == ""


@pytest.mark.asyncio
async def test_assess_coherence_llm_raises_returns_none(monkeypatch) -> None:
    """`_assess_coherence` returns None when the LLM client raises (timeout/httpx/etc.)."""
    from app.modules.person_dossier import (
        PersonDossier,
        _assess_coherence,
    )

    dossier = PersonDossier(
        email_hash="a" * 64,
        profiles=["https://linkedin.com/in/jane"],
        source_modules=["socmint"],
    )
    bad_client = AsyncMock()
    bad_client.chat_completion = AsyncMock(side_effect=RuntimeError("simulated LLM failure"))
    tag = await _assess_coherence(dossier, bad_client, "stub prompt")
    assert tag is None


@pytest.mark.asyncio
async def test_assess_coherence_non_dict_response_returns_none() -> None:
    """`_assess_coherence` returns None when the LLM returns a non-dict (string/list/etc.)."""
    from app.modules.person_dossier import PersonDossier, _assess_coherence

    dossier = PersonDossier(
        email_hash="a" * 64,
        profiles=[],
        source_modules=["socmint"],
    )
    bad_client = AsyncMock()
    bad_client.chat_completion = AsyncMock(return_value="not a dict")
    tag = await _assess_coherence(dossier, bad_client, "stub prompt")
    assert tag is None


@pytest.mark.asyncio
async def test_assess_coherence_empty_verdicts_returns_none() -> None:
    """`_assess_coherence` returns None when verdicts list is empty."""
    from app.modules.person_dossier import PersonDossier, _assess_coherence

    dossier = PersonDossier(
        email_hash="a" * 64,
        profiles=[],
        source_modules=["socmint"],
    )
    client = AsyncMock()
    client.chat_completion = AsyncMock(
        return_value={"verdicts": [], "summary": "stub", "recommended_action": "CONTINUE"}
    )
    tag = await _assess_coherence(dossier, client, "stub prompt")
    assert tag is None


@pytest.mark.asyncio
async def test_assess_coherence_non_dict_verdict_returns_none() -> None:
    """`_assess_coherence` returns None when the first verdict is not a dict."""
    from app.modules.person_dossier import PersonDossier, _assess_coherence

    dossier = PersonDossier(
        email_hash="a" * 64,
        profiles=[],
        source_modules=["socmint"],
    )
    client = AsyncMock()
    client.chat_completion = AsyncMock(
        return_value={"verdicts": ["not-a-dict"]}
    )
    tag = await _assess_coherence(dossier, client, "stub prompt")
    assert tag is None


@pytest.mark.asyncio
async def test_assess_coherence_invalid_verdict_string_returns_none() -> None:
    """`_assess_coherence` returns None when verdict string is not in the allowed set."""
    from app.modules.person_dossier import PersonDossier, _assess_coherence

    dossier = PersonDossier(
        email_hash="a" * 64,
        profiles=[],
        source_modules=["socmint"],
    )
    client = AsyncMock()
    client.chat_completion = AsyncMock(
        return_value={"verdicts": [{"verdict": "MAYBE"}]}
    )
    tag = await _assess_coherence(dossier, client, "stub prompt")
    assert tag is None


@pytest.mark.asyncio
async def test_run_includes_social_profile_in_dossier(fresh_db, mock_llm) -> None:
    """A SOCIAL_PROFILE finding bucketed via metadata.email_hash populates `profiles[]`."""
    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
                ("socmint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
                ("breach_data", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
                ("employee_osint", ModuleStatus.COMPLETED, ModuleTier.TIER_3),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="jane@example.com",
            confidence=0.9,
        )
        _seed_finding(
            db,
            "test-job-1",
            "socmint",
            FindingType.SOCIAL_PROFILE,
            value="https://linkedin.com/in/jane-doe",
            confidence=0.85,
            finding_metadata={"email_hash": "a" * 64},
        )
    # Email hash of jane@example.com is deterministic; pre-compute and align.
    from app.utils.encryption import hash_email

    jane_hash = hash_email("jane@example.com")
    # Re-seed socmint with the correct email_hash to match jane@example.com.
    with SessionLocal() as db:
        # Wipe and re-seed socmint finding with the correct hash.
        socmint_run = (
            db.query(ModuleRun)
            .filter(ModuleRun.job_id == "test-job-1", ModuleRun.module_name == "socmint")
            .first()
        )
        socmint_finding = (
            db.query(FindingModel)
            .filter(FindingModel.module_run_id == socmint_run.id)
            .first()
        )
        socmint_finding.finding_metadata = {"email_hash": jane_hash}
        db.commit()
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    meta = output.findings[0].finding_metadata
    assert "https://linkedin.com/in/jane-doe" in meta["profiles"]
    assert "socmint" in meta["source_modules"]


@pytest.mark.asyncio
async def test_run_encryption_key_invalid_logs_warning(fresh_db, mock_llm) -> None:
    """An invalid Fernet key surfaces a warning in ModuleOutput.errors (no identity_map row)."""
    from cryptography.fernet import Fernet

    bogus_key = Fernet.generate_key().decode()[:-4] + "AAAA"  # truncated → invalid
    import os
    os.environ["PERSON_DOSSIER_ENCRYPTION_KEY"] = bogus_key
    from app.config import get_settings
    get_settings.cache_clear()

    try:
        module = PersonDossierModule()
        with SessionLocal() as db:
            _seed_job_with_module_runs(
                db,
                modules=[
                    ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
                ],
            )
            _seed_finding(
                db,
                "test-job-1",
                "email_harvesting",
                FindingType.EMAIL,
                value="badkey@example.com",
                confidence=0.8,
            )
        output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
        assert len(output.findings) == 1
        # The dossier is emitted, but persona_id ends with _no_pii (no row stored).
        assert output.findings[0].value.endswith("_no_pii")
        assert any("encryption key" in e for e in output.errors)
    finally:
        os.environ["PERSON_DOSSIER_ENCRYPTION_KEY"] = ""
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_run_idempotent_repeated_run_no_duplicate(fresh_db, mock_llm) -> None:
    """Re-running the module for the same job + email_hash does NOT emit a 2nd dossier.

    This exercises the IdentityMap UNIQUE(job_id, email_hash) integrity-error
    branch in `_store_identity_map` (lines 738-740).
    """
    from cryptography.fernet import Fernet
    import os

    fernet_key = Fernet.generate_key().decode()
    os.environ["PERSON_DOSSIER_ENCRYPTION_KEY"] = fernet_key
    from app.config import get_settings

    get_settings.cache_clear()

    try:
        module = PersonDossierModule()
        with SessionLocal() as db:
            _seed_job_with_module_runs(
                db,
                modules=[
                    ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
                ],
            )
            _seed_finding(
                db,
                "test-job-1",
                "email_harvesting",
                FindingType.EMAIL,
                value="idem@example.com",
                confidence=0.9,
            )
        # First run — emits 1 dossier + 1 identity_map row.
        first = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
        assert len(first.findings) == 1

        # Second run — bucket is empty (already dossiered) → no dossier.
        second = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
        assert second.findings == []
    finally:
        os.environ["PERSON_DOSSIER_ENCRYPTION_KEY"] = ""
        get_settings.cache_clear()


def test_make_llm_client_returns_client() -> None:
    """`_make_llm_client` instantiates an LLMClient (lazy import path, line 745-747)."""
    from app.modules.person_dossier import PersonDossierModule

    client = PersonDossierModule._make_llm_client()
    # We don't assert on the exact type (avoid importing LLMClient here) —
    # just that a non-None object was returned.
    assert client is not None
    # And close() is callable (LLMClient contract).
    assert hasattr(client, "close")


@pytest.mark.asyncio
async def test_assess_coherence_valid_verdict_string_returns_value() -> None:
    """`_assess_coherence` returns the verdict string when it is in the allowed set (lines 378)."""
    from app.modules.person_dossier import PersonDossier, _assess_coherence

    dossier = PersonDossier(
        email_hash="a" * 64,
        profiles=["https://linkedin.com/in/jane"],
        source_modules=["socmint"],
    )
    client = AsyncMock()
    client.chat_completion = AsyncMock(
        return_value={"verdicts": [{"verdict": "HIGH"}]}
    )
    tag = await _assess_coherence(dossier, client, "stub prompt")
    assert tag == "HIGH"


@pytest.mark.asyncio
async def test_assess_coherence_verdict_is_none_returns_none() -> None:
    """`_assess_coherence` returns None when first verdict's `verdict` field is None (line 375)."""
    from app.modules.person_dossier import PersonDossier, _assess_coherence

    dossier = PersonDossier(
        email_hash="a" * 64,
        profiles=[],
        source_modules=["socmint"],
    )
    client = AsyncMock()
    client.chat_completion = AsyncMock(
        return_value={"verdicts": [{"verdict": None}]}
    )
    tag = await _assess_coherence(dossier, client, "stub prompt")
    assert tag is None


@pytest.mark.asyncio
async def test_run_coherence_assigned_when_llm_returns_valid_verdict(
    fresh_db, monkeypatch
) -> None:
    """End-to-end: when LLM returns HIGH, dossier.coherence = 'HIGH' (lines 514-516)."""
    from app.modules.person_dossier import PersonDossierModule
    from unittest.mock import AsyncMock

    coherence_mock = AsyncMock()
    coherence_mock.chat_completion = AsyncMock(
        return_value={"verdicts": [{"verdict": "MEDIUM"}]}
    )
    coherence_mock.close = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "app.modules.person_dossier.PersonDossierModule._make_llm_client",
        staticmethod(lambda: coherence_mock),
    )

    module = PersonDossierModule()
    with SessionLocal() as db:
        _seed_job_with_module_runs(
            db,
            modules=[
                ("email_harvesting", ModuleStatus.COMPLETED, ModuleTier.TIER_1),
            ],
        )
        _seed_finding(
            db,
            "test-job-1",
            "email_harvesting",
            FindingType.EMAIL,
            value="coherent@example.com",
            confidence=0.9,
        )
    output = await module.run(ModuleInput(target="example.com", job_id="test-job-1"))
    assert len(output.findings) == 1
    assert output.findings[0].finding_metadata["coherence"] == "MEDIUM"


def test_store_identity_map_handles_integrity_error(fresh_db, monkeypatch) -> None:
    """`_store_identity_map` catches UNIQUE violation silently (lines 740-742)."""
    from app.modules.person_dossier import PersonDossierModule
    from app.utils.encryption import hash_email
    from cryptography.fernet import Fernet

    fernet_key = Fernet.generate_key()
    monkeypatch.setenv("PERSON_DOSSIER_ENCRYPTION_KEY", fernet_key.decode())
    from app.config import get_settings

    get_settings.cache_clear()

    email = "dup@example.com"
    email_hash = hash_email(email)
    job_id = "test-job-1"

    # Pre-seed a row so the next insert raises IntegrityError.
    with SessionLocal() as db:
        _seed_job_with_module_runs(db, job_id=job_id)
        db.add(
            IdentityMap(
                job_id=job_id,
                email_hash=email_hash,
                encrypted_email=b"existing" .decode("ascii"),
                persona_id="Persona_000",
            )
        )
        db.commit()

    errors: list[str] = []
    with SessionLocal() as db:
        result = PersonDossierModule._store_identity_map(
            db=db,
            job_id=job_id,
            email_hash=email_hash,
            persona_id="Persona_001",
            plaintext=email,
            encryption_key=fernet_key,
            errors=errors,
        )
    assert result is True  # existing row wins — still "ok"
    assert errors == []


def test_build_dossier_credential_exposure_in_bucket() -> None:
    """`_build_dossier` extracts breach_exposures from CREDENTIAL_EXPOSURE findings (line 670).

    CREDENTIAL_EXPOSURE findings never bucket through `_group_by_email_hash`
    in normal flow (10-char SHA-1 prefix fails the 64-char check), but the
    `_build_dossier` defensive branch still handles them when called directly.
    """
    from app.modules.person_dossier import PersonDossierModule

    email_hash = "a" * 64
    credential_finding = Finding(
        type=FindingType.CREDENTIAL_EXPOSURE,
        value="3_breaches",
        source="breach_data",
        confidence=0.8,
        finding_metadata={"email_hash_prefix": "abc1234567", "breach_count": 3},
    )
    dossier = PersonDossierModule._build_dossier(
        email_hash,
        [("breach_data", credential_finding)],
    )
    assert len(dossier.breach_exposures) == 1
    assert dossier.breach_exposures[0]["breach_count"] == 3
    assert "breach_data" in dossier.source_modules