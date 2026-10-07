"""Handoff subsystem: public contract for Phase 2 consumers."""

from app.handoff.bridge import generate_handoff_for_job
from app.handoff.exporter import export_handoff
from app.handoff.importer import import_handoff
from app.handoff.schema import (
    HandoffCertificate,
    HandoffConfirmedTarget,
    HandoffCredentialsExposure,
    HandoffPacket,
    HandoffRecommendedModule,
    HandoffSource,
    HandoffTarget,
    HandoffTechStack,
)

__all__ = [
    "HandoffPacket",
    "HandoffSource",
    "HandoffTarget",
    "HandoffConfirmedTarget",
    "HandoffTechStack",
    "HandoffCredentialsExposure",
    "HandoffRecommendedModule",
    "HandoffCertificate",
    "export_handoff",
    "import_handoff",
    "generate_handoff_for_job",
]
