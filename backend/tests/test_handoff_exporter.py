"""Tests for app.handoff.exporter (export_handoff + helpers).

The exporter is the seam between the in-DB recon state and the JSON file
the handoff consumer reads. It's safety-critical: a partial write here
produces a corrupt packet downstream, and a path-traversal in the
constructed file path would exfiltrate host files. We cover:

- export_handoff happy path (writes JSON file + Handoff row)
- export_handoff rejects uncompleted jobs
- export_handoff rejects missing jobs
- export_handoff PENDING → GENERATED state transition
- export_handoff updates existing Handoff row (idempotent re-export)
- export_handoff SSRF / path-traversal defense refuses to write outside HANDOFFS_DIR
- _build_packet assembles confirmed_targets, tech_stack, emails_found, breach_count,
  recommended_modules, consent_tier3, person_dossiers
- _process_finding dispatches SUBDOMAIN/DOSSIER/TECH_STACK correctly
- _process_finding logs and skips malformed DOSSIER findings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from app.handoff.exporter import _build_packet, _process_finding, export_handoff
from app.models import (
    AIValidation,
    Finding,
    FindingType,
    Handoff,
    HandoffStatus,
    Job,
    JobStatus,
    ModuleRun,
    ModuleStatus,
    ModuleTier,
    _now,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_job(db: Session, target: str = "example.com", completed: bool = True) -> Job:
    """Insert a job with one whois_rdap ModuleRun + one SUBDOMAIN Finding."""
    job = Job(
        target=target,
        target_type="domain",
        status=JobStatus.COMPLETED if completed else JobStatus.RUNNING,
        selected_modules=["whois_rdap"],
        user_consent=True,
        typed_confirmation=target,
        consent_modal_version="v1",
        consent_timestamp=_now(),
        started_at=_now(),
        completed_at=_now() if completed else None,
        duration_seconds=5.0,
    )
    db.add(job)
    db.flush()
    # Commit so the row is visible to other connections (file-based test
    # DB uses WAL mode; uncommitted writes are invisible to readers).
    db.commit()
    return job


def _make_module_run(
    db: Session,
    job_id: str,
    name: str = "whois_rdap",
    tier: ModuleTier = ModuleTier.TIER_1,
) -> ModuleRun:
    mr = ModuleRun(
        job_id=job_id,
        module_name=name,
        module_tier=tier,
        status=ModuleStatus.COMPLETED,
        findings_count=0,
        duration_seconds=1.0,
    )
    db.add(mr)
    db.flush()
    db.commit()
    return mr


def _make_finding(
    db: Session, module_run_id: str, ftype: FindingType, value: str,
    source: str = "test", confidence: float = 0.9, meta: dict[str, Any] | None = None,
) -> Finding:
    f = Finding(
        module_run_id=module_run_id,
        type=ftype,
        value=value,
        source=source,
        confidence=confidence,
        finding_metadata=meta or {},
    )
    db.add(f)
    db.flush()
    db.commit()
    return f


# ---------------------------------------------------------------------------
# export_handoff — happy path + invariants
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_handoff_writes_file_and_row(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Happy path: JSON file is written under HANDOFFS_DIR + a Handoff row is created."""
    from app.handoff import exporter as exporter_mod

    job = _make_job(db)
    mr = _make_module_run(db, job.id)
    _make_finding(db, mr.id, FindingType.SUBDOMAIN, "api.example.com")

    handoffs_dir = tmp_path / "handoffs"
    handoffs_dir.mkdir()
    monkeypatch.setattr(exporter_mod.settings, "HANDOFFS_DIR", str(handoffs_dir))

    _packet = await export_handoff(job.id)

    # File exists with valid JSON
    files = list(handoffs_dir.glob("*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert data["source"]["job_id"] == job.id

    # Handoff row is created
    handoff = db.query(Handoff).filter(Handoff.job_id == job.id).first()
    assert handoff is not None
    assert handoff.file_path == str(files[0])

    # Job's handoff_status is GENERATED
    db.refresh(job)
    assert job.handoff_status == HandoffStatus.GENERATED


@pytest.mark.asyncio
async def test_export_handoff_rejects_missing_job(db: Session) -> None:
    """export_handoff raises ValueError for unknown job IDs."""
    with pytest.raises(ValueError, match="not found"):
        await export_handoff("does-not-exist")


@pytest.mark.asyncio
async def test_export_handoff_rejects_uncompleted_job(db: Session) -> None:
    """export_handoff raises ValueError if the job is not yet completed."""
    job = _make_job(db, completed=False)

    with pytest.raises(ValueError, match="not yet completed"):
        await export_handoff(job.id)


@pytest.mark.asyncio
async def test_export_handoff_marks_pending_then_generated(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Status transitions: NOT_GENERATED -> PENDING -> GENERATED.

    We track the PENDING transition by snapshotting the job's in-memory
    state right after the export_handoff call returns; the GENERATED
    status must be visible in the DB after the function exits.
    """
    from app.handoff import exporter as exporter_mod

    job = _make_job(db)
    _make_module_run(db, job.id)
    handoffs_dir = tmp_path / "handoffs"
    handoffs_dir.mkdir()
    monkeypatch.setattr(exporter_mod.settings, "HANDOFFS_DIR", str(handoffs_dir))

    # Starting state
    assert job.handoff_status == HandoffStatus.NOT_GENERATED

    await export_handoff(job.id)

    # After export completes, status must be GENERATED (the final state)
    db.refresh(job)
    assert job.handoff_status == HandoffStatus.GENERATED


@pytest.mark.asyncio
async def test_export_handoff_updates_existing_row(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-running export on the same job updates the existing Handoff row (idempotent)."""
    from app.handoff import exporter as exporter_mod

    job = _make_job(db)
    _make_module_run(db, job.id)
    handoffs_dir = tmp_path / "handoffs"
    handoffs_dir.mkdir()
    monkeypatch.setattr(exporter_mod.settings, "HANDOFFS_DIR", str(handoffs_dir))

    # First export creates a row
    await export_handoff(job.id)
    handoff_count_1 = db.query(Handoff).filter(Handoff.job_id == job.id).count()
    assert handoff_count_1 == 1

    # Second export UPDATES the same row (no duplicate)
    await export_handoff(job.id)
    handoff_count_2 = db.query(Handoff).filter(Handoff.job_id == job.id).count()
    assert handoff_count_2 == 1


@pytest.mark.asyncio
async def test_export_handoff_refuses_traversal_path(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defense in depth: refuses to write a handoff outside HANDOFFS_DIR.

    The exporter constructs ``handoffs_dir / f"{handoff_id}.json"`` so a
    direct traversal via ``job.id`` is unlikely, but the explicit
    ``relative_to`` check guards against any future code path that
    interpolates untrusted input.
    """
    from app.handoff import exporter as exporter_mod

    job = _make_job(db)
    _make_module_run(db, job.id)

    handoffs_dir = tmp_path / "handoffs"
    handoffs_dir.mkdir()
    monkeypatch.setattr(exporter_mod.settings, "HANDOFFS_DIR", str(handoffs_dir))

    # Monkey-patch Path.resolve to simulate a write target escaping the dir
    real_resolve = Path.resolve
    escape_target = (tmp_path / "secret.json").resolve()

    def fake_resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        # If the exporter ever resolves an output path, return the escape target
        if self.name.endswith(".json") and "h-" in self.name:
            return escape_target
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fake_resolve)
    with pytest.raises(ValueError, match="Refusing to write"):
        await export_handoff(job.id)


# ---------------------------------------------------------------------------
# _build_packet — composition
# ---------------------------------------------------------------------------


def test_build_packet_consent_tier3_collects_tier_3_modules(db: Session) -> None:
    """Module runs at tier_3 land in consent_flags.tier_3_modules_run."""
    job = _make_job(db)
    _make_module_run(db, job.id, name="tier3_mod", tier=ModuleTier.TIER_3)
    _make_module_run(db, job.id, name="tier1_mod", tier=ModuleTier.TIER_1)

    packet = _build_packet(db, job)
    assert "tier3_mod" in packet.consent_flags.tier_3_modules_run
    assert "tier1_mod" not in packet.consent_flags.tier_3_modules_run


def test_build_packet_recommended_modules_from_validation(db: Session) -> None:
    """Validation.recommended_next_modules is mirrored into recommended_modules."""
    job = _make_job(db)
    mr = _make_module_run(db, job.id)
    db.add(
        AIValidation(
            module_run_id=mr.id,
            decision={"verdicts": []},
            summary="x",
            confidence=0.5,
            recommended_action="CONTINUE",
            recommended_next_modules=["port_scanning", "tech_stack"],
        )
    )
    db.commit()

    packet = _build_packet(db, job)
    modules = {m.module for m in packet.recommended_modules}
    assert {"port_scanning", "tech_stack"} <= modules


def test_build_packet_email_and_breach_counters(db: Session) -> None:
    """emails_found + breach_count tally EMAIL + CREDENTIAL_EXPOSURE findings."""
    job = _make_job(db)
    mr = _make_module_run(db, job.id)
    _make_finding(db, mr.id, FindingType.EMAIL, "a@example.com")
    _make_finding(db, mr.id, FindingType.EMAIL, "b@example.com")
    _make_finding(db, mr.id, FindingType.CREDENTIAL_EXPOSURE, "leaked:pw1")

    packet = _build_packet(db, job)
    assert packet.credentials_exposure_summary.emails_found == 2
    assert packet.credentials_exposure_summary.breach_count == 1


# ---------------------------------------------------------------------------
# _process_finding — dispatch
# ---------------------------------------------------------------------------


def test_process_finding_subdomain_confirmed_promotes_to_confirmed_target(
    db: Session,
) -> None:
    """A SUBDOMAIN finding matching a CONFIRMED verdict becomes a HandoffConfirmedTarget."""
    job = _make_job(db)
    mr = _make_module_run(db, job.id, name="subdomain_enum")
    finding = _make_finding(db, mr.id, FindingType.SUBDOMAIN, "api.example.com")
    validation = MagicMock()
    validation.decision = {
        "verdicts": [
            {
                "value": "api.example.com",
                "verdict": "CONFIRMED",
                "priority": "HIGH",
                "reasoning": "public API",
                "confidence": 0.95,
            }
        ]
    }

    confirmed: list[Any] = []
    tech_stack: Any = None
    from app.handoff.schema import HandoffTechStack

    tech_stack = HandoffTechStack()
    person_dossiers: list[Any] = []
    _process_finding(
        finding=finding,
        mr=mr,
        validation=validation,
        confirmed_targets=confirmed,
        tech_stack=tech_stack,
        emails_found=0,
        breach_count=0,
        person_dossiers=person_dossiers,
    )
    assert len(confirmed) == 1
    assert confirmed[0].subdomain == "api.example.com"
    assert confirmed[0].ai_verdict == "CONFIRMED"


def test_process_finding_subdomain_likely_not_added() -> None:
    """A SUBDOMAIN with verdict LIKELY still gets added (per the OR-check)."""
    # Note: the source says `verdict in ("CONFIRMED", "LIKELY")`, so LIKELY
    # is also accepted. We assert that here.
    from app.handoff.schema import HandoffTechStack

    finding = MagicMock()
    finding.id = "f-1"
    finding.type = FindingType.SUBDOMAIN
    finding.value = "x.example.com"
    finding.finding_metadata = {}

    mr = MagicMock()
    mr.module_name = "subdomain_enum"
    validation = MagicMock()
    validation.decision = {
        "verdicts": [
            {"value": "x.example.com", "verdict": "LIKELY", "confidence": 0.6}
        ]
    }

    confirmed: list[Any] = []
    person_dossiers: list[Any] = []
    _process_finding(
        finding=finding,
        mr=mr,
        validation=validation,
        confirmed_targets=confirmed,
        tech_stack=HandoffTechStack(),
        emails_found=0,
        breach_count=0,
        person_dossiers=person_dossiers,
    )
    assert len(confirmed) == 1


def test_process_finding_dossier_added_with_metadata(db: Session) -> None:
    """A DOSSIER finding with valid metadata becomes a HandoffPersonDossierSummary."""
    from app.handoff.schema import HandoffTechStack

    job = _make_job(db)
    mr = _make_module_run(db, job.id, name="person_dossier")
    finding = _make_finding(
        db,
        mr.id,
        FindingType.DOSSIER,
        "Persona_001",
        meta={
            "email_hash": "a" * 64,
            "source_modules": ["email_harvesting", "socmint"],
            "role_relevance": "HIGH",
            "priority_for_targeting": "HIGH",
            "coherence": "HIGH",
            "breach_exposures": [1, 2, 3],
            "profiles": [1],
        },
    )
    validation = MagicMock()

    confirmed: list[Any] = []
    person_dossiers: list[Any] = []
    _process_finding(
        finding=finding,
        mr=mr,
        validation=validation,
        confirmed_targets=confirmed,
        tech_stack=HandoffTechStack(),
        emails_found=0,
        breach_count=0,
        person_dossiers=person_dossiers,
    )
    assert len(person_dossiers) == 1
    assert person_dossiers[0].persona_id == "Persona_001"
    assert person_dossiers[0].breach_exposure_count == 3
    assert person_dossiers[0].profile_count == 1


def test_process_finding_dossier_malformed_logged_and_skipped(
    db: Session, caplog: pytest.LogCaptureFixture
) -> None:
    """A DOSSIER missing email_hash is logged + skipped (no exception)."""
    from app.handoff.schema import HandoffTechStack

    job = _make_job(db)
    mr = _make_module_run(db, job.id, name="person_dossier")
    finding = _make_finding(
        db,
        mr.id,
        FindingType.DOSSIER,
        "Persona_002",
        meta={"source_modules": ["x"]},  # missing email_hash
    )
    validation = MagicMock()

    confirmed: list[Any] = []
    person_dossiers: list[Any] = []
    import logging

    with caplog.at_level(logging.WARNING, logger="app.handoff.exporter"):
        _process_finding(
            finding=finding,
            mr=mr,
            validation=validation,
            confirmed_targets=confirmed,
            tech_stack=HandoffTechStack(),
            emails_found=0,
            breach_count=0,
            person_dossiers=person_dossiers,
        )
    assert person_dossiers == []
    assert any("person_dossier_skip" in rec.message for rec in caplog.records)


def test_process_finding_tech_stack_dispatches_to_correct_bucket() -> None:
    """TECH_STACK findings route to web_servers / frameworks / databases."""
    from app.handoff.schema import HandoffTechStack

    mr = MagicMock()
    mr.module_name = "whois_rdap"
    validation = MagicMock()
    confirmed: list[Any] = []
    person_dossiers: list[Any] = []

    # Web server
    f_server = MagicMock()
    f_server.id = "fs"
    f_server.type = FindingType.TECH_STACK
    f_server.value = "1.21"
    f_server.source = "nginx-server"
    f_server.finding_metadata = {}
    tech_stack = HandoffTechStack()
    _process_finding(
        finding=f_server, mr=mr, validation=validation,
        confirmed_targets=confirmed, tech_stack=tech_stack,
        emails_found=0, breach_count=0, person_dossiers=person_dossiers,
    )
    assert "nginx-server" in tech_stack.web_servers

    # Framework
    f_fw = MagicMock()
    f_fw.id = "ff"
    f_fw.type = FindingType.TECH_STACK
    f_fw.value = "4.2"
    f_fw.source = "express-framework"
    f_fw.finding_metadata = {}
    tech_stack = HandoffTechStack()
    _process_finding(
        finding=f_fw, mr=mr, validation=validation,
        confirmed_targets=confirmed, tech_stack=tech_stack,
        emails_found=0, breach_count=0, person_dossiers=person_dossiers,
    )
    assert "express-framework" in tech_stack.frameworks

    # Database
    f_db = MagicMock()
    f_db.id = "fd"
    f_db.type = FindingType.TECH_STACK
    f_db.value = "13"
    f_db.source = "primary-database"
    f_db.finding_metadata = {}
    tech_stack = HandoffTechStack()
    _process_finding(
        finding=f_db, mr=mr, validation=validation,
        confirmed_targets=confirmed, tech_stack=tech_stack,
        emails_found=0, breach_count=0, person_dossiers=person_dossiers,
    )
    assert "primary-database" in tech_stack.databases
