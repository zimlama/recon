"""Tests for the handoff subsystem."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from app.handoff.schema import (
    HandoffPacket,
    HandoffSource,
    HandoffTarget,
    HandoffConfirmedTarget,
)
from app.handoff.importer import import_handoff


def test_handoff_packet_minimal() -> None:
    """A minimal HandoffPacket can be created."""
    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.utcnow(),
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
            completed_at=datetime.utcnow(),
        ),
        target=HandoffTarget(primary_domain="example.com"),
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
            completed_at=datetime.utcnow(),
        ),
        target=HandoffTarget(primary_domain="example.com"),
    )
    json_str = original.model_dump_json()
    parsed = HandoffPacket.model_validate_json(json_str)
    assert parsed.schema_version == original.schema_version
    assert parsed.target.primary_domain == original.target.primary_domain


def test_handoff_packet_rejects_extra_fields() -> None:
    """HandoffPacket rejects extra fields (strict schema)."""
    with pytest.raises(Exception):  # ValidationError
        HandoffPacket.model_validate({
            "source": {
                "version": "0.1.0",
                "job_id": "x",
                "completed_at": datetime.utcnow().isoformat(),
            },
            "target": {"primary_domain": "example.com"},
            "unknown_field": "should fail",  # extra="forbid"
        })


def test_import_handoff_validates_schema(tmp_path: Path) -> None:
    """import_handoff validates a JSON file against the schema."""
    packet = HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id="test-123",
            completed_at=datetime.utcnow(),
        ),
        target=HandoffTarget(primary_domain="example.com"),
    )
    json_path = tmp_path / "handoff.json"
    json_path.write_text(packet.model_dump_json(indent=2), encoding="utf-8")

    loaded = import_handoff(json_path)
    assert loaded.schema_version == packet.schema_version


def test_import_handoff_missing_file(tmp_path: Path) -> None:
    """import_handoff raises FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        import_handoff(tmp_path / "nonexistent.json")
