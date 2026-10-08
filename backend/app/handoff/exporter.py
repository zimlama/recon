"""Handoff exporter — Job → HandoffPacket → JSON file."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.handoff.schema import (
    HandoffCertificate,
    HandoffConfirmedTarget,
    HandoffConsentFlags,
    HandoffCredentialsExposure,
    HandoffPacket,
    HandoffPersonDossierSummary,
    HandoffRecommendedModule,
    HandoffShodanExposure,
    HandoffSource,
    HandoffTarget,
    HandoffTechStack,
)
from app.models import (
    AIValidation,
    Finding,
    FindingType,
    Handoff,
    HandoffStatus,
    Job,
    ModuleRun,
)

logger = logging.getLogger(__name__)
settings = get_settings()


async def export_handoff(job_id: str) -> HandoffPacket:
    """Build a HandoffPacket from a completed job and persist it.

    Returns the HandoffPacket (also written to disk + DB).

    Side effects:
      - Marks `Job.handoff_status = PENDING` on entry so a partial export
        (crash between mark and write) leaves the DB in a recoverable
        state rather than the ambiguous NOT_GENERATED.
      - Marks `Job.handoff_status = GENERATED` on success.
      - Leaves the status untouched on failure — the caller (`bridge.py`)
        is responsible for setting FAILED so we don't double-write.
    """
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        if not job.completed_at:
            raise ValueError(f"Job {job_id} not yet completed")

        # Mark PENDING up-front so a crash mid-export is observable.
        job.handoff_status = HandoffStatus.PENDING
        db.commit()

        packet = _build_packet(db, job)

        # Write JSON file. Use a temp file + atomic rename so a crash
        # mid-write never leaves a half-written JSON on disk that future
        # readers would parse as corrupt.
        handoffs_dir = Path(settings.HANDOFFS_DIR)
        handoffs_dir.mkdir(parents=True, exist_ok=True)
        handoff_id = f"h-{job.completed_at.strftime('%Y%m%d')}-{job.id[:8]}"
        file_path = handoffs_dir / f"{handoff_id}.json"

        # SSRF defense (defense in depth): verify the resolved path is under
        # the configured HANDOFFS_DIR. The route layer guards against caller-
        # controlled job_id, but this writer-level check protects against any
        # future code path that constructs file_path from untrusted sources.
        handoffs_dir_resolved = Path(settings.HANDOFFS_DIR).resolve()
        file_path_resolved = file_path.resolve()
        try:
            file_path_resolved.relative_to(handoffs_dir_resolved)
        except ValueError as e:
            raise ValueError(
                f"Refusing to write handoff file outside {handoffs_dir_resolved}: "
                f"{file_path_resolved} ({e})"
            ) from e

        json_data = json.dumps(
            packet.model_dump(mode="json"), indent=2, ensure_ascii=False
        )
        fd, tmp_path = tempfile.mkstemp(suffix=".json.tmp", dir=handoffs_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json_data)
            os.replace(tmp_path, file_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        # Persist DB row. If the DB write fails, the JSON file is already
        # on disk but the Handoff row doesn't exist — that's recoverable
        # by re-running export_handoff (idempotent), so we let it raise.
        existing = db.query(Handoff).filter(Handoff.job_id == job_id).first()
        if existing is None:
            db.add(
                Handoff(
                    job_id=job_id,
                    schema_version=packet.schema_version,
                    packet=packet.model_dump(mode="json"),
                    file_path=str(file_path),
                )
            )
        else:
            existing.packet = packet.model_dump(mode="json")
            existing.file_path = str(file_path)
        # Mark GENERATED only after both the file and the DB row are committed.
        # If we crash before this line, the next startup sweeper (or a manual
        # re-export) can detect handoff_status=PENDING and recover.
        job.handoff_status = HandoffStatus.GENERATED
        db.commit()

    logger.info("handoff_exported", job_id=job_id, file_path=str(file_path))
    return packet


def _build_packet(db: Session, job: Job) -> HandoffPacket:
    """Build a HandoffPacket from a Job and its ModuleRuns."""
    module_runs = db.query(ModuleRun).filter(ModuleRun.job_id == job.id).all()

    # Confirmed targets (from subdomain_enum + AI validation)
    confirmed_targets: list[HandoffConfirmedTarget] = []
    tech_stack = HandoffTechStack()
    emails_found = 0
    breach_count = 0
    recommended_modules: list[HandoffRecommendedModule] = []
    consent_tier3: list[str] = []
    person_dossiers: list[HandoffPersonDossierSummary] = []

    for mr in module_runs:
        if mr.module_tier.value == "tier_3":
            consent_tier3.append(mr.module_name)

        # Find AI validation for this module run
        validation = (
            db.query(AIValidation)
            .filter(AIValidation.module_run_id == mr.id)
            .first()
        )

        # Recommended modules from validation
        if validation and validation.recommended_next_modules:
            for module_name in validation.recommended_next_modules:
                recommended_modules.append(
                    HandoffRecommendedModule(
                        module=module_name,
                        priority="MEDIUM",
                        rationale=f"Recommended by {mr.module_name} validation",
                    )
                )

        # Process findings
        for finding in mr.findings:
            if finding.type == FindingType.SUBDOMAIN and validation:
                # Confirmed target
                verdict = next(
                    (v for v in validation.decision.get("verdicts", []) if v.get("value") == finding.value),
                    None,
                )
                if verdict and verdict.get("verdict") in ("CONFIRMED", "LIKELY"):
                    confirmed_targets.append(
                        HandoffConfirmedTarget(
                            subdomain=finding.value,
                            ips=[],  # TODO: enrich with DNS data
                            priority_for_next_phase=verdict.get("priority", "MEDIUM"),
                            ai_reasoning=verdict.get("reasoning", ""),
                            ai_verdict=verdict.get("verdict", "LIKELY"),
                            ai_confidence=verdict.get("confidence", 0.5),
                            shodan_exposure=HandoffShodanExposure() if mr.module_name == "shodan_censys" else None,
                        )
                    )

            if finding.type == FindingType.EMAIL:
                emails_found += 1

            if finding.type == FindingType.CREDENTIAL_EXPOSURE:
                breach_count += 1

            # PR 4 — PersonDossier extraction (additive, backwards-compatible).
            # The handoff consumer sees the pseudonym + provenance but never
            # the plaintext email. See design.md §8 / spec.md REQ-020.
            if finding.type == FindingType.DOSSIER:
                meta = finding.finding_metadata or {}
                # Defensive: malformed DOSSIER findings are skipped, not raised.
                try:
                    person_dossiers.append(
                        HandoffPersonDossierSummary(
                            persona_id=finding.value,
                            email_hash=meta["email_hash"],
                            source_modules=list(meta.get("source_modules", [])),
                            role_relevance=meta.get("role_relevance", "LOW"),
                            priority_for_targeting=meta.get("priority_for_targeting", "LOW"),
                            confidence=float(finding.confidence),
                            coherence=meta.get("coherence"),
                            breach_exposure_count=len(meta.get("breach_exposures", [])),
                            profile_count=len(meta.get("profiles", [])),
                        )
                    )
                except (KeyError, ValueError, TypeError) as e:
                    logger.warning(
                        "person_dossier_skip malformed finding id=%s error=%s",
                        finding.id,
                        e,
                    )

            if finding.type == FindingType.TECH_STACK:
                # Add to tech_stack
                name = finding.source
                version = finding.value
                if "server" in name.lower() or "nginx" in version.lower():
                    tech_stack.web_servers.setdefault(name, []).append(version)
                elif "framework" in name.lower():
                    tech_stack.frameworks.setdefault(name, []).append(version)
                elif "database" in name.lower() or "postgres" in version.lower() or "mysql" in version.lower():
                    tech_stack.databases.setdefault(name, []).append(version)

    return HandoffPacket(
        source=HandoffSource(
            version="0.1.0",
            job_id=job.id,
            completed_at=job.completed_at,
        ),
        target=HandoffTarget(
            primary_domain=job.target,
            authorization_scope=f"domain {job.target}",
            active_scan_authorized=False,
        ),
        confirmed_targets=confirmed_targets,
        tech_stack_summary=tech_stack,
        credentials_exposure_summary=HandoffCredentialsExposure(
            emails_found=emails_found,
            breach_count=breach_count,
        ),
        recommended_modules=recommended_modules,
        person_dossiers=person_dossiers,
        consent_flags=HandoffConsentFlags(
            tier_3_modules_run=consent_tier3,
            white_hat_only=True,
        ),
    )


__all__ = ["export_handoff"]
