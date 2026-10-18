"""Tests for the handoff subsystem."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.handoff.importer import import_handoff
from app.handoff.schema import (
    HandoffConfirmedTarget,
    HandoffPacket,
    HandoffSource,
    HandoffTarget,
)


def test_handoff_packet_minimal() -> None:
    """A minimal HandoffPacket can be created."""
    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.now(UTC),
        ),
        target=HandoffTarget(
            primary_domain="example.com",
            authorization_scope="domain example.com",
        ),
    )
    assert packet.schema_version == "1.0.0"
    assert packet.target.primary_domain == "example.com"
    assert len(packet.do_not_scan) >= 5  # default banned list


def test_handoff_packet_with_confirmed_targets() -> None:
    """HandoffPacket can include confirmed targets."""
    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.now(UTC),
        ),
        target=HandoffTarget(
            primary_domain="example.com",
            authorization_scope="domain example.com",
        ),
        confirmed_targets=[
            HandoffConfirmedTarget(
                subdomain="api.example.com",
                ips=["1.2.3.4"],
                priority_for_next_phase="HIGH",
                ai_reasoning="Public API with known vulnerable nginx",
                ai_verdict="CONFIRMED",
                ai_confidence=0.95,
            ),
        ],
    )
    assert len(packet.confirmed_targets) == 1
    assert packet.confirmed_targets[0].subdomain == "api.example.com"


def test_handoff_packet_serialization() -> None:
    """HandoffPacket can be serialized to JSON and back."""
    original = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.now(UTC),
        ),
        target=HandoffTarget(
            primary_domain="example.com",
            authorization_scope="domain example.com",
        ),
    )
    json_str = original.model_dump_json()
    parsed = HandoffPacket.model_validate_json(json_str)
    assert parsed.schema_version == original.schema_version
    assert parsed.target.primary_domain == original.target.primary_domain


def test_handoff_packet_rejects_extra_fields() -> None:
    """HandoffPacket rejects extra fields (strict schema)."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HandoffPacket.model_validate(
            {
                "source": {
                    "version": "0.1.0",
                    "job_id": "x",
                    "completed_at": datetime.now(UTC).isoformat(),
                },
                "target": {"primary_domain": "example.com"},
                "unknown_field": "should fail",  # extra="forbid"
            }
        )


# ---------------------------------------------------------------------------
# PR 4 — PersonDossier summary in handoff packet
# ---------------------------------------------------------------------------


def test_handoff_packet_with_person_dossiers() -> None:
    """HandoffPacket accepts a list of HandoffPersonDossierSummary entries.

    PR 4 (REQ-016 AC-016.1 + design.md §8): additive, non-breaking.
    """
    from app.handoff.schema import HandoffPersonDossierSummary

    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.now(UTC),
        ),
        target=HandoffTarget(
            primary_domain="example.com",
            authorization_scope="domain example.com",
        ),
        person_dossiers=[
            HandoffPersonDossierSummary(
                persona_id="Persona_001",
                email_hash="a" * 64,
                source_modules=["email_harvesting", "socmint"],
                role_relevance="HIGH",
                priority_for_targeting="HIGH",
                confidence=0.95,
                coherence="HIGH",
                breach_exposure_count=3,
                profile_count=1,
            ),
        ],
    )
    assert len(packet.person_dossiers) == 1
    assert packet.person_dossiers[0].persona_id == "Persona_001"
    assert packet.person_dossiers[0].email_hash == "a" * 64
    assert packet.person_dossiers[0].breach_exposure_count == 3


def test_handoff_packet_default_person_dossiers_empty() -> None:
    """HandoffPacket.person_dossiers defaults to [] (additive, non-breaking)."""
    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.now(UTC),
        ),
        target=HandoffTarget(
            primary_domain="example.com",
            authorization_scope="domain example.com",
        ),
    )
    assert packet.person_dossiers == []


def test_handoff_person_dossier_summary_rejects_plaintext_email() -> None:
    """HandoffPersonDossierSummary has NO `email` field (privacy invariant)."""
    from pydantic import ValidationError

    from app.handoff.schema import HandoffPersonDossierSummary

    with pytest.raises(ValidationError):
        HandoffPersonDossierSummary(
            persona_id="Persona_001",
            email="jane@example.com",  # plaintext — forbidden
            email_hash="a" * 64,
            source_modules=[],
            role_relevance="LOW",
            priority_for_targeting="LOW",
            confidence=0.5,
            breach_exposure_count=0,
            profile_count=0,
        )


def test_handoff_person_dossier_summary_rejects_short_email_hash() -> None:
    """email_hash MUST be exactly 64 lowercase hex (per design.md REQ-020)."""
    from pydantic import ValidationError

    from app.handoff.schema import HandoffPersonDossierSummary

    with pytest.raises(ValidationError):
        HandoffPersonDossierSummary(
            persona_id="Persona_001",
            email_hash="abc",  # too short
            source_modules=[],
            role_relevance="LOW",
            priority_for_targeting="LOW",
            confidence=0.5,
            breach_exposure_count=0,
            profile_count=0,
        )


def test_handoff_person_dossier_summary_role_relevance_literal() -> None:
    """role_relevance MUST be HIGH/MEDIUM/LOW."""
    from pydantic import ValidationError

    from app.handoff.schema import HandoffPersonDossierSummary

    with pytest.raises(ValidationError):
        HandoffPersonDossierSummary(
            persona_id="Persona_001",
            email_hash="a" * 64,
            source_modules=[],
            role_relevance="MAYBE",  # not a valid literal
            priority_for_targeting="LOW",
            confidence=0.5,
            breach_exposure_count=0,
            profile_count=0,
        )


def test_handoff_packet_serialization_with_dossiers() -> None:
    """Dossiers round-trip through JSON model_dump / model_validate."""
    from app.handoff.schema import HandoffPersonDossierSummary

    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.now(UTC),
        ),
        target=HandoffTarget(
            primary_domain="example.com",
            authorization_scope="domain example.com",
        ),
        person_dossiers=[
            HandoffPersonDossierSummary(
                persona_id="Persona_001",
                email_hash="b" * 64,
                source_modules=["socmint"],
                role_relevance="MEDIUM",
                priority_for_targeting="MEDIUM",
                confidence=0.7,
                breach_exposure_count=1,
                profile_count=2,
            ),
        ],
    )
    json_data = packet.model_dump_json()
    loaded = HandoffPacket.model_validate_json(json_data)
    assert len(loaded.person_dossiers) == 1
    assert loaded.person_dossiers[0].persona_id == "Persona_001"
    assert loaded.person_dossiers[0].email_hash == "b" * 64


def test_import_handoff_validates_schema(tmp_path: Path) -> None:
    """import_handoff validates a JSON file against the schema."""
    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.now(UTC),
        ),
        target=HandoffTarget(
            primary_domain="example.com",
            authorization_scope="domain example.com",
        ),
    )
    json_path = tmp_path / "handoff.json"
    json_path.write_text(packet.model_dump_json(indent=2), encoding="utf-8")

    loaded = import_handoff(json_path)
    assert loaded.schema_version == packet.schema_version


def test_import_handoff_missing_file(tmp_path: Path) -> None:
    """import_handoff raises FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        import_handoff(tmp_path / "nonexistent.json")


# ---------------------------------------------------------------------------
# Security regressions — path traversal + filename sanitization (Fix #1, #2)
# ---------------------------------------------------------------------------


def test_safe_filename_part_strips_crlf() -> None:
    """CRLF and other unsafe chars are stripped to '_'."""
    from app.utils.network import safe_filename_part

    # Classic CRLF header-injection payload
    assert "\r" not in safe_filename_part("foo\r\nX-Evil: bar")
    assert "\n" not in safe_filename_part("foo\r\nbar")
    # All replaced with underscores, no control chars survive
    assert safe_filename_part("foo\r\nbar").replace("_", "") == "foobar"


def test_safe_filename_part_keeps_safe_chars() -> None:
    """Allowed chars (A-Za-z0-9._-) pass through unchanged."""
    from app.utils.network import safe_filename_part

    assert safe_filename_part("example.com") == "example.com"
    assert safe_filename_part("sub-domain_1") == "sub-domain_1"
    assert safe_filename_part("a1.2_b-3") == "a1.2_b-3"


def test_safe_filename_part_rejects_path_separators_and_quotes() -> None:
    """Path separators and quotes are replaced, never passed verbatim."""
    from app.utils.network import safe_filename_part

    # '../' .. 'passwd' would be a path-traversal vector in a filename
    out = safe_filename_part("../etc/passwd")
    assert "/" not in out
    assert ".." not in out  # stripped trailing dots
    assert "\\" not in safe_filename_part("..\\windows\\system")
    assert '"' not in safe_filename_part('foo"bar')
    assert "'" not in safe_filename_part("foo'bar")
    assert ":" not in safe_filename_part("foo:bar")


def test_safe_filename_part_caps_length() -> None:
    """Long inputs are truncated to 63 chars."""
    from app.utils.network import safe_filename_part

    long_input = "a" * 500
    assert len(safe_filename_part(long_input)) == 63


def test_safe_filename_part_handles_empty_or_unsafe_only() -> None:
    """Empty / unsafe-only inputs fall back to 'unknown'."""
    from app.utils.network import safe_filename_part

    assert safe_filename_part("") == "unknown"
    # Inputs that strip down to nothing after .strip().strip('.') → "unknown".
    assert safe_filename_part("...") == "unknown"
    # Whitespace-only becomes all underscores — `_` IS a safe char, so it
    # stays. This is intentional: defense-in-depth keeps the field
    # non-empty rather than silently dropping it.
    assert safe_filename_part("   ") == "___"
    # Non-strings short-circuit to "unknown" (no exception).
    assert safe_filename_part(None) == "unknown"  # type: ignore[arg-type]
    assert safe_filename_part(123) == "unknown"  # type: ignore[arg-type]
    # Slashes (path traversal) get replaced, not kept verbatim.
    assert "/" not in safe_filename_part("///")
    assert "\\" not in safe_filename_part("\\\\\\")


def test_safe_filename_part_strips_leading_trailing_dots() -> None:
    """Leading/trailing dots are stripped to avoid hidden files / .. escapes."""
    from app.utils.network import safe_filename_part

    assert safe_filename_part("...example.com...") == "example.com"
    assert not safe_filename_part(".bashrc").startswith(".")


def test_resolve_under_handoffs_rejects_traversal(tmp_path: Path) -> None:
    """Path traversal escapes from HANDOFFS_DIR return 403."""
    from fastapi import HTTPException

    from app.config import Settings
    from app.routes.handoff import _resolve_under_handoffs

    cfg = Settings(HANDOFFS_DIR=str(tmp_path / "handoffs"))
    (tmp_path / "handoffs").mkdir()

    # Inside root → resolved Path returned
    inside = tmp_path / "handoffs" / "abc.json"
    assert _resolve_under_handoffs(str(inside), cfg) == inside.resolve()

    # Outside root (parent traversal) → 403
    evil = tmp_path / "handoffs" / ".." / "secret.json"
    with pytest.raises(HTTPException) as exc:
        _resolve_under_handoffs(str(evil), cfg)
    assert exc.value.status_code == 403


def test_resolve_under_handoffs_rejects_absolute_escape(tmp_path: Path) -> None:
    """Absolute paths outside HANDOFFS_DIR return 403."""
    from fastapi import HTTPException

    from app.config import Settings
    from app.routes.handoff import _resolve_under_handoffs

    cfg = Settings(HANDOFFS_DIR=str(tmp_path / "handoffs"))
    (tmp_path / "handoffs").mkdir()

    with pytest.raises(HTTPException) as exc:
        _resolve_under_handoffs("/etc/passwd", cfg)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# Route-layer pre-check: download_handoff returns 400 when job is not completed
# (Fix for L-001 handoff "race condition" — actual cause was route inconsistency)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_download_handoff_returns_400_when_job_not_completed(
    client, db
) -> None:
    """download_handoff MUST return 400 (not 500) when the job exists but
    has not reached COMPLETED.

    Symmetry: get_job_handoff has this check at L54-58; download_handoff
    lacked it, causing the user-observed "Job <id> not yet completed" 500 +
    misleading handoff_status=FAILED pollution.

    OWASP API8: appropriate HTTP status (4xx for client errors, not 5xx).
    Defense in depth: route pre-check + exporter's own completed_at check.
    """
    from app.models import HandoffStatus, Job, JobStatus, _now

    # Arrange: a RUNNING job with no Handoff row (the auto-generation path
    # would otherwise be triggered).
    job = Job(
        target="example.com",
        target_type="domain",
        status=JobStatus.RUNNING,
        selected_modules=["whois_rdap"],
        user_consent=True,
        typed_confirmation="example.com",
        consent_modal_version="v1",
        consent_timestamp=_now(),
        started_at=_now(),
        completed_at=None,
        duration_seconds=None,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    job_id = job.id

    # Act
    response = await client.get(f"/api/v1/jobs/{job_id}/handoff/download")

    # Assert: 400 (not 500) — appropriate HTTP semantics
    assert response.status_code == 400, (
        f"expected 400 for incomplete job, got {response.status_code}: {response.text}"
    )
    body = response.json()
    assert "detail" in body
    assert "not completed" in body["detail"].lower(), (
        f"error message should mention 'not completed', got: {body['detail']!r}"
    )

    # Assert: handoff_status is NOT polluted to FAILED for client errors
    db.refresh(job)
    assert job.handoff_status != HandoffStatus.FAILED, (
        "client error (job not ready) must NOT mark handoff_status=FAILED"
    )
    assert not job.error_message or "not yet completed" not in (job.error_message or ""), (
        f"error_message should not contain 'not yet completed' for client 400, "
        f"got: {job.error_message!r}"
    )
