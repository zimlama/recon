"""Handoff importer — JSON file → HandoffPacket (Pydantic validation)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.handoff.schema import HandoffPacket

logger = logging.getLogger(__name__)


def import_handoff(json_path: str | Path) -> HandoffPacket:
    """Read a handoff JSON file and validate it against the schema.

    Raises:
        FileNotFoundError: if the file doesn't exist
        ValidationError: if the file doesn't match the schema
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Handoff file not found: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    packet = HandoffPacket.model_validate(raw)

    logger.info(
        "handoff_imported",
        path=str(path),
        schema_version=packet.schema_version,
        targets=len(packet.confirmed_targets),
    )
    return packet


__all__ = ["import_handoff"]
