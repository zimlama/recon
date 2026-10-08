# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Person dossier aggregator — Tier 3 (white-hat gated).

Cross-module aggregator that reads completed findings from sibling modules
(``employee_osint``, ``socmint``, ``breach_data``, optionally
``email_harvesting``) for the same ``job_id``, groups them by SHA-256
email_hash, and emits one ``Finding(type=DOSSIER)`` per unique identity.

**This module is the privacy boundary.** Raw email plaintext is scoped to
``_resolve_plaintext_email`` and flows directly into
``encrypt_email()`` → ``IdentityMap.encrypted_email``. The plaintext never
crosses into:

  - ``logger`` calls,
  - the LLM prompt payload (only ``email_hash`` crosses the wire),
  - ``Finding.finding_metadata`` (the Pydantic schema forbids extras),
  - the handoff export.

MITRE ATT&CK: T1589.002 (gather victim email addresses — aggregator over
already-gathered data, no new network IO).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import IntegrityError

from app.config import get_settings
from app.models import (
    FindingType,
    IdentityMap,
    Job,
    ModuleStatus,
    ModuleTier,
)
from app.models import (
    ModuleRun as ModuleRunModel,
)
from app.modules.base import (
    BaseReconModule,
    Finding,
    ModuleInput,
    ModuleOutput,
)
from app.utils.encryption import (
    EncryptionKeyMissingError,
    encrypt_email,
    hash_email,
)

logger = logging.getLogger(__name__)


# Closed list of sibling modules whose findings this aggregator reads.
# Findings from other modules are not bucketed per-email — they're ignored.
#
# `email_harvesting` is included because its EMAIL findings carry the raw
# email value that both feeds the bucket hash and provides the plaintext
# for the encrypted identity_map row (per spec.md AC-016.2 / REQ-020).
SOURCE_MODULES: tuple[str, ...] = (
    "employee_osint",
    "socmint",
    "breach_data",
    "email_harvesting",
)

# Hard cap on DB reads per run (anti-block — per design.md §9).
MAX_SIBLING_FINDINGS = 10_000

# Per-dossier AI cap (anti-block — per design.md §7 / REQ-021 AC-021.7).
AI_MAX_TOKENS = 256
AI_TIMEOUT_SECONDS = 30.0
AI_TEMPERATURE = 0.1


# ---- Pydantic schema (REQ-018) ----


class PersonDossier(BaseModel):
    """Structured cross-module dossier for one email identity.

    Embedded inside ``Finding.finding_metadata`` for DOSSIER findings.
    ``extra="forbid"`` keeps the wire shape stable across releases and
    prevents accidental addition of a plaintext ``email`` field.
    """

    model_config = ConfigDict(extra="forbid")

    email_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 hex pseudonym (REQ-020)",
    )

    @field_validator("email_hash", mode="before")
    @classmethod
    def _email_hash_must_be_str(cls, v: Any) -> Any:
        # Defensive: Pydantic v2 default coerces some types; we want to be
        # explicit so a bytes payload is rejected (per A-018.d).
        if not isinstance(v, str):
            raise ValueError("email_hash must be a str")
        return v
    profiles: list[str] = Field(
        default_factory=list,
        description="SOCIAL_PROFILE URLs (from socmint)",
    )
    breach_exposures: list[dict[str, Any]] = Field(
        default_factory=list,
        description="CREDENTIAL_EXPOSURE metadata blobs",
    )
    role_relevance: str = Field(
        default="LOW",
        description="Role relevance tag",
    )
    priority_for_targeting: str = Field(
        default="LOW",
        description="Priority for downstream targeting",
    )
    source_modules: list[str] = Field(
        default_factory=list,
        description="Unique module names that reported this email",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Aggregated confidence (max + 0.1 boost, capped 1.0)",
    )
    coherence: str | None = Field(
        default=None,
        description="AI-assessed tag (HIGH/MEDIUM/LOW/NONE), populated post-validation",
    )

    @field_validator("role_relevance", "priority_for_targeting")
    @classmethod
    def _check_priority_literal(cls, v: str) -> str:
        if v not in {"HIGH", "MEDIUM", "LOW"}:
            raise ValueError(f"must be HIGH/MEDIUM/LOW, got {v!r}")
        return v

    @field_validator("coherence")
    @classmethod
    def _check_coherence_literal(cls, v: str | None) -> str | None:
        if v is not None and v not in {"HIGH", "MEDIUM", "LOW", "NONE"}:
            raise ValueError(f"must be HIGH/MEDIUM/LOW/NONE, got {v!r}")
        return v


# ---- Helpers (REQ-017) ----


def _extract_email_hash(finding: Finding) -> str | None:
    """Extract a SHA-256 ``email_hash`` from a sibling Finding.

    Rules (per spec.md REQ-017):

    - ``EMAIL`` → ``hash_email(finding.value)``
    - ``USERNAME`` / ``SOCIAL_PROFILE`` → ``finding.finding_metadata["email_hash"]``
      when it is exactly 64 hex chars
    - ``CREDENTIAL_EXPOSURE`` → ``None`` (its 10-char SHA-1 prefix is rejected
      by the 64-char length check; correlation happens via domain-join in
      ``_collect_orphan_breaches_and_attach``)
    - other types → ``None``

    Defensive: returns ``None`` for any malformed metadata rather than
    raising (per A-017.d — ``finding_metadata is None`` is safe).
    """
    if finding.type == FindingType.EMAIL:
        if not finding.value:
            return None
        return hash_email(finding.value)

    if finding.type in (FindingType.USERNAME, FindingType.SOCIAL_PROFILE):
        meta = finding.finding_metadata
        if not isinstance(meta, dict):
            return None
        candidate = meta.get("email_hash")
        if not isinstance(candidate, str):
            return None
        if len(candidate) != 64:
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", candidate):
            return None
        return candidate

    # CREDENTIAL_EXPOSURE + everything else: no per-email hash.
    return None


def _domain_of_email(email: str) -> str:
    """Return the domain part of an email (lowercased). Empty string if no '@'."""
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].lower().strip()


def _group_by_email_hash(
    findings_with_modules: list[tuple[str, Finding]],
    already_dossiered: set[str],
) -> dict[str, list[tuple[str, Finding]]]:
    """Group sibling findings by their SHA-256 email_hash.

    Findings with no extractable hash are dropped. Hashes already present
    in ``already_dossiered`` are dropped (idempotency).
    """
    bucket: dict[str, list[tuple[str, Finding]]] = {}
    for module_name, finding in findings_with_modules:
        eh = _extract_email_hash(finding)
        if eh is None:
            continue
        if eh in already_dossiered:
            continue
        bucket.setdefault(eh, []).append((module_name, finding))
    return bucket


def _aggregate_confidence(findings: list[Finding]) -> float:
    """Compute the dossier's confidence (REQ-019).

    - 0 sources → 0.0 (defensive default)
    - 1 source  → max source confidence
    - 2+ sources → max + 0.1, capped at 1.0
    """
    if not findings:
        return 0.0
    max_conf = max(f.confidence for f in findings)
    if len(findings) == 1:
        return max_conf
    return min(max_conf + 0.1, 1.0)


def _resolve_plaintext_email(findings: list[Finding]) -> str | None:
    """Return the first non-empty plaintext EMAIL finding value, lowercased.

    The plaintext NEVER leaves this function — it's the single entry point
    that touches the raw email outside of ``_extract_email_hash``. It is
    passed directly to ``encrypt_email()`` and then garbage-collected.
    """
    for finding in findings:
        if finding.type == FindingType.EMAIL and finding.value:
            return finding.value.strip().lower()
    return None


def _collect_orphan_breaches_and_attach(
    sibling_findings: list[tuple[str, Finding]],
    bucket: dict[str, list[tuple[str, Finding]]],
) -> tuple[list[tuple[str, Finding, str]], list[str]]:
    """Two-step breach correlation (REQ-017 AC-017.4 / AC-017.5).

    Walks ALL sibling findings (not just bucketed ones) because
    CREDENTIAL_EXPOSURE never gets bucketed by email_hash — its 10-char
    SHA-1 prefix fails the 64-char check.

    For each CREDENTIAL_EXPOSURE finding:

    - If its metadata ``domain`` matches the domain of any EMAIL finding
      (across any bucket) → attach to the matching dossier.
    - Otherwise → orphan: surfaced via ``ModuleOutput.errors`` as
      ``"orphan breach: <email_hash_prefix> for <domain>"``.

    Returns:
        ``(attached, orphans)`` where each ``attached`` entry is
        ``(module_name, breach_finding, target_email_hash)`` and each
        ``orphan`` is the error string.
    """
    # Step 1: index EMAIL findings by domain → email_hash.
    domains_by_hash: dict[str, str] = {}
    for email_hash, items in bucket.items():
        for _module_name, finding in items:
            if finding.type == FindingType.EMAIL:
                d = _domain_of_email(finding.value)
                if d:
                    domains_by_hash[email_hash] = d
                break

    hashes_by_domain: dict[str, list[str]] = {}
    for email_hash, domain in domains_by_hash.items():
        hashes_by_domain.setdefault(domain, []).append(email_hash)

    # Step 2: walk sibling findings; classify each CREDENTIAL_EXPOSURE.
    attached: list[tuple[str, Finding, str]] = []
    orphans: list[str] = []
    for module_name, finding in sibling_findings:
        if finding.type != FindingType.CREDENTIAL_EXPOSURE:
            continue
        meta = (
            finding.finding_metadata
            if isinstance(finding.finding_metadata, dict)
            else {}
        )
        breach_domain = (
            meta.get("domain", "")
            if isinstance(meta.get("domain", ""), str)
            else ""
        ).lower()
        if breach_domain and hashes_by_domain.get(breach_domain):
            target = hashes_by_domain[breach_domain][0]
            attached.append((module_name, finding, target))
            continue
        orphans.append(
            f"orphan breach: {meta.get('email_hash_prefix', '?')} "
            f"for {breach_domain or '?'}"
        )

    return attached, orphans


# ---- AI coherence helper (REQ-021) ----


async def _assess_coherence(
    dossier: PersonDossier,
    llm_client: Any,
    system_prompt: str,
) -> str | None:
    """Ask the LLM to assess coherence of one dossier.

    - 1 LLM call per dossier (capped at ``AI_MAX_TOKENS=256``).
    - 30s timeout via ``asyncio.wait_for``.
    - Maps HIGH/MEDIUM/LOW/NONE from the first verdict to the dossier's
      ``coherence`` field. Returns ``None`` on any failure mode:
      ValidationError, TimeoutError, httpx errors, malformed JSON, or
      stub-mode (LLMClient returns empty verdicts).
    """
    user_payload = {
        "email_hash": dossier.email_hash,
        "profiles": dossier.profiles,
        "breach_exposures_count": len(dossier.breach_exposures),
        "source_modules": dossier.source_modules,
        "role_relevance": dossier.role_relevance,
    }
    user_message = (
        "Validate this person dossier and respond with the LDMValidationResult JSON.\n"
        f"Target email_hash: {dossier.email_hash}\n\n"
        f"{user_payload!r}"
    )
    try:
        response = await asyncio.wait_for(
            llm_client.chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                response_format={"type": "json_object"},
                temperature=AI_TEMPERATURE,
                max_tokens=AI_MAX_TOKENS,
            ),
            timeout=AI_TIMEOUT_SECONDS,
        )
    except Exception as e:
        logger.warning("coherence_llm_failed error=%s", e)
        return None

    if not isinstance(response, dict):
        return None
    verdicts = response.get("verdicts") or []
    if not verdicts:
        return None
    first = verdicts[0]
    if not isinstance(first, dict):
        return None
    raw_verdict = first.get("verdict")
    if not isinstance(raw_verdict, str):
        return None
    if raw_verdict not in {"HIGH", "MEDIUM", "LOW", "NONE"}:
        return None
    return raw_verdict


# ---- Module class ----


class PersonDossierModule(BaseReconModule):
    """Cross-module person dossier aggregator (PR 4).

    Tier 3, white-hat gated (``requires_consent=True``). Reads completed
    findings from sibling modules (``employee_osint``, ``socmint``,
    ``breach_data``) for the same ``job_id`` and emits one
    ``Finding(type=DOSSIER)`` per unique identity. Encrypted email storage
    is opt-in via the ``PERSON_DOSSIER_ENCRYPTION_KEY`` env var; without
    it, dossiers still emit but ``identity_map`` rows are skipped (with a
    warning in ``ModuleOutput.errors``).

    Dependency wiring: option (b) from design.md §12 Q1 — person_dossier
    polls sibling ``ModuleRun.status`` and skips if any sibling is still
    ``RUNNING``. Localized; no risk to the other 14 modules. The expected
    operational pattern is that operators append ``person_dossier`` last
    in ``selected_modules``.
    """

    name = "person_dossier"
    description = (
        "Cross-module person dossier aggregator — merges findings from "
        "socmint, employee_osint, breach_data into one DOSSIER per identity "
        "(SHA-256 pseudonym, encrypted raw email at rest, no plaintext in "
        "logs/AI/handoff)"
    )
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1589.002"]
    requires_api_keys: list[str] = []  # no network IO
    requires_consent = True  # PII handling (encrypted at rest)
    estimated_duration_seconds = 30  # bounded — pure DB + 1 LLM call per dossier
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:  # noqa: C901 — orchestrator role
        """Build PersonDossier findings for the job.

        Pipeline (each step a helper):
          1. _load_sibling_state — poll sibling ModuleRun.status.
          2. _load_source_findings — read sibling Finding rows.
          3. _group_findings_for_processing — bucket by email_hash + attach breaches.
          4. _build_dossiers — build one PersonDossier per bucket + coherence.
          5. _emit_findings — write IdentityMap rows + emit DOSSIER findings.
        """
        self.validate_target_format(input.target)
        start = time.time()

        # Lazy import to avoid pulling SQLAlchemy at module-import time.
        from app.database import SessionLocal

        with SessionLocal() as db:
            job = db.get(Job, input.job_id) if input.job_id else None
            if job is None:
                raise ValueError(f"job not found: {input.job_id}")

            skipped = self._load_sibling_state(db, job.id)
            if skipped is not None:
                return skipped.as_module_output(self.name, start)

            sibling_rows = self._load_source_findings(db, job.id)
            if not sibling_rows:
                return ModuleOutput(
                    module=self.name,
                    findings=[],
                    duration_seconds=time.time() - start,
                    errors=["no completed sibling modules"],
                )

            grouping = self._group_findings_for_processing(
                db, job.id, sibling_rows
            )
            errors = list(grouping["orphan_breaches"])

            dossiers, plaintext_by_hash = self._build_dossiers(
                grouping["bucket"],
                grouping["attached_breaches"],
            )

            await self._apply_coherence(dossiers)

            findings = self._emit_findings(
                db,
                job.id,
                dossiers,
                plaintext_by_hash,
                errors,
            )
            db.commit()

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    # ----------------------------------------------------------------
    # run() helpers (each ≤50 lines, single responsibility)
    # ----------------------------------------------------------------

    def _load_sibling_state(
        self, db: Any, job_id: str
    ) -> "ModuleOutput | _SkipSignal | None":  # noqa: F821 — forward
        """Poll sibling ModuleRun rows.

        If any sibling is still RUNNING, signal a skip via the
        ``_SkipSignal`` stub (the orchestrator turns it into an empty
        ModuleOutput). Returns None when all siblings are terminal.
        """
        sibling_states = self._sibling_module_states(db, job_id)
        running = [
            name
            for name, status in sibling_states.items()
            if status == ModuleStatus.RUNNING
        ]
        if running:
            return _SkipSignal(
                f"sibling still running: {','.join(sorted(running))} — dossier skipped"
            )
        return None

    def _load_source_findings(
        self, db: Any, job_id: str
    ) -> list[tuple[Any, str]]:
        """Read sibling Finding rows (DB rows, not Pydantic)."""
        return self._query_sibling_finding_rows(db, job_id)

    def _group_findings_for_processing(
        self,
        db: Any,
        job_id: str,
        sibling_rows: list[tuple[Any, str]],
    ) -> dict[str, Any]:
        """Idempotency + bucket + breach join.

        Returns a dict with ``bucket``, ``attached_breaches``, and
        ``orphan_breaches`` so the orchestrator can run them
        sequentially without re-reading the DB.
        """
        sibling_findings: list[tuple[str, Finding]] = [
            (module_name, self._row_to_finding(row))
            for row, module_name in sibling_rows
        ]
        already_dossiered = self._already_dossiered_email_hashes(db, job_id)
        bucket = _group_by_email_hash(sibling_findings, already_dossiered)
        attached_breaches, orphan_breaches = _collect_orphan_breaches_and_attach(
            sibling_findings, bucket
        )
        return {
            "bucket": bucket,
            "attached_breaches": attached_breaches,
            "orphan_breaches": orphan_breaches,
        }

    def _build_dossiers(
        self,
        bucket: dict[str, list[tuple[str, Finding]]],
        attached_breaches: list[tuple[str, Finding, str]],
    ) -> tuple[list["PersonDossier"], dict[str, str | None]]:
        """Build one PersonDossier per bucket + the plaintext-email map.

        Returns ``(dossiers, plaintext_by_hash)`` — ``plaintext_by_hash``
        is the per-dossier plaintext that flows into _store_identity_map.
        Breaches attached via domain-join are folded into the matching
        dossier's ``breach_exposures`` + ``source_modules``.
        """
        llm_client = self._make_llm_client()
        # llm_client closure is held by `_assess_coherence` until
        # `_apply_coherence` completes. We deliberately don't close
        # here — _apply_coherence closes after the coherence calls
        # return. See ``_apply_coherence`` for the matching close.
        self._pending_llm_client = llm_client

        dossiers: list[PersonDossier] = []
        plaintext_by_hash: dict[str, str | None] = {}
        for email_hash, items in bucket.items():
            dossiers.append(self._build_dossier(email_hash, items))
            plaintext_by_hash[email_hash] = _resolve_plaintext_email(
                [f for _m, f in items]
            )

        for module_name, breach_finding, target_hash in attached_breaches:
            for d in dossiers:
                if d.email_hash == target_hash:
                    if isinstance(breach_finding.finding_metadata, dict):
                        d.breach_exposures.append(breach_finding.finding_metadata)
                    if module_name not in d.source_modules:
                        d.source_modules.append(module_name)
                    break

        return dossiers, plaintext_by_hash

    async def _apply_coherence(
        self, dossiers: list["PersonDossier"]
    ) -> None:
        """Run LLM coherence on each dossier (best-effort).

        Closes the LLM client when done. Per-dossier failures don't
        block dossier emission — the helper returns and lets the
        orchestrator continue.
        """
        llm_client = getattr(self, "_pending_llm_client", None)
        system_prompt = self.get_ai_prompt()
        try:
            for dossier in dossiers:
                try:
                    tag = await _assess_coherence(
                        dossier, llm_client, system_prompt
                    )
                    if tag is not None:
                        dossier.coherence = tag
                except Exception as e:  # pragma: no cover — defensive
                    logger.warning(
                        "coherence_assessment_failed hash=%s err=%s",
                        dossier.email_hash[:8],
                        e,
                    )
        finally:
            if llm_client is not None:
                with contextlib.suppress(Exception):
                    await llm_client.close()
                self._pending_llm_client = None

    def _emit_findings(
        self,
        db: Any,
        job_id: str,
        dossiers: list["PersonDossier"],
        plaintext_by_hash: dict[str, str | None],
        errors: list[str],
    ) -> list[Finding]:
        """Write IdentityMap rows + emit DOSSIER Findings.

        Iterates ``dossiers`` with a ``persona_counter`` to produce
        ``Persona_001``, ``Persona_002``, ... and applies the
        ``_no_pii`` suffix when ``_store_identity_map`` did NOT
        insert an encrypted row.
        """
        findings: list[Finding] = []
        encryption_key = self._encryption_key_bytes()
        for persona_counter, dossier in enumerate(dossiers, start=1):
            base_persona = f"Persona_{persona_counter:03d}"
            plaintext = plaintext_by_hash.get(dossier.email_hash)
            row_inserted = self._store_identity_map(
                db=db,
                job_id=job_id,
                email_hash=dossier.email_hash,
                persona_id=base_persona,
                plaintext=plaintext,
                encryption_key=encryption_key,
                errors=errors,
            )
            persona_id = (
                base_persona if row_inserted else f"{base_persona}_no_pii"
            )
            findings.append(
                Finding(
                    type=FindingType.DOSSIER,
                    value=persona_id,
                    source=self.name,
                    confidence=dossier.confidence,
                    finding_metadata=dossier.model_dump(),
                )
            )
        return findings

    def get_ai_prompt(self) -> str:
        """System prompt for the LLM coherence assessment (REQ-021).

        The LLM NEVER sees plaintext email — only the SHA-256 hash and
        synthetic metadata.
        """
        return (
            "You are validating a cross-module PERSON DOSSIER for a target "
            "organization.\n"
            "The dossier aggregates findings from SOCMINT, EMPLOYEE_OSINT, "
            "and BREACH_DATA modules into a single identity keyed by "
            "SHA-256(email).\n\n"
            "For the dossier, classify COHERENCE as one of:\n"
            "- HIGH:    profiles + breach_exposures + role_relevance all "
            "describe ONE person\n"
            "- MEDIUM:  profiles + breach_exposures agree, role inferred only\n"
            "- LOW:     sources describe different people (same hash by "
            "coincidence)\n"
            "- NONE:    insufficient data to judge (return NONE if "
            "breaches_only or profiles_only)\n\n"
            "Respond with strict JSON matching the LDMValidationResult "
            "schema. Use a single verdict whose `value` is the email_hash.\n\n"
            "PRIVACY INVARIANTS (binding):\n"
            "- You will NEVER see the raw email — only the SHA-256 hash.\n"
            "- Do NOT infer or guess the raw email from context.\n"
            "- Do NOT suggest outreach, password spray, or unauthorized use.\n"
            "- If asked to expand the hash, refuse.\n\n"
            "Return ONLY the structured JSON. No prose."
        )

    # ---- Module-level helpers (DB queries, encryption plumbing) ----

    @staticmethod
    def _sibling_module_states(db: Any, job_id: str) -> dict[str, str]:
        """Return a {module_name: ModuleStatus} dict for sibling runs.

        Used by the dependency-polling check (Q1 option b).
        """
        rows = (
            db.query(ModuleRunModel)
            .filter(
                ModuleRunModel.job_id == job_id,
                ModuleRunModel.module_name.in_(SOURCE_MODULES),
            )
            .all()
        )
        return {row.module_name: row.status for row in rows}

    @staticmethod
    def _query_sibling_finding_rows(db: Any, job_id: str) -> list[tuple[Any, str]]:
        """Read all completed sibling findings for the job (DB rows).

        Returns ``[(FindingModel, module_name)]`` — callers convert to the
        Pydantic ``Finding`` shape. Bounded by ``MAX_SIBLING_FINDINGS``
        (per design.md §9).
        """
        from app.models import Finding as FindingModel

        rows = (
            db.query(FindingModel, ModuleRunModel.module_name)
            .join(ModuleRunModel, FindingModel.module_run_id == ModuleRunModel.id)
            .filter(
                ModuleRunModel.job_id == job_id,
                ModuleRunModel.module_name.in_(SOURCE_MODULES),
                ModuleRunModel.status == ModuleStatus.COMPLETED,
            )
            .limit(MAX_SIBLING_FINDINGS)
            .all()
        )
        return [(row, module_name) for row, module_name in rows]

    @staticmethod
    def _row_to_finding(row: Any) -> Finding:
        """Convert a SQLAlchemy ``FindingModel`` to the Pydantic ``Finding``."""
        return Finding(
            type=row.type,
            value=row.value,
            source=row.source,
            confidence=row.confidence,
            finding_metadata=row.finding_metadata,
        )

    @staticmethod
    def _already_dossiered_email_hashes(db: Any, job_id: str) -> set[str]:
        """Return the set of email_hashes that already have an identity_map row.

        Used for idempotency on re-runs.
        """
        rows = (
            db.query(IdentityMap.email_hash)
            .filter(IdentityMap.job_id == job_id)
            .all()
        )
        return {row[0] for row in rows}

    @staticmethod
    def _build_dossier(
        email_hash: str, items: list[tuple[str, Finding]]
    ) -> PersonDossier:
        """Build one PersonDossier from a bucket of (module_name, Finding)."""
        profiles: list[str] = []
        breach_exposures: list[dict[str, Any]] = []
        source_modules: list[str] = []
        for module_name, finding in items:
            if module_name not in source_modules:
                source_modules.append(module_name)
            if finding.type == FindingType.SOCIAL_PROFILE:
                profiles.append(finding.value)
            elif finding.type == FindingType.CREDENTIAL_EXPOSURE and isinstance(
                finding.finding_metadata, dict
            ):
                breach_exposures.append(finding.finding_metadata)

        # Role/priority inference is intentionally conservative for v1 — both
        # default to LOW. A follow-up could route this through the LLM or a
        # heuristic per source module.
        return PersonDossier(
            email_hash=email_hash,
            profiles=profiles,
            breach_exposures=breach_exposures,
            role_relevance="LOW",
            priority_for_targeting="LOW",
            source_modules=source_modules,
            confidence=_aggregate_confidence([f for _m, f in items]),
            coherence=None,
        )

    @staticmethod
    def _encryption_key_bytes() -> bytes | None:
        """Return the Fernet key bytes from settings, or None if unset."""
        settings = get_settings()
        raw = settings.PERSON_DOSSIER_ENCRYPTION_KEY
        if not raw:
            return None
        return raw.encode("ascii")

    @staticmethod
    def _store_identity_map(
        db: Any,
        job_id: str,
        email_hash: str,
        persona_id: str,
        plaintext: str | None,
        encryption_key: bytes | None,
        errors: list[str],
    ) -> bool:
        """Insert one IdentityMap row (idempotent).

        Returns ``True`` if a row exists for this (job_id, email_hash),
        ``False`` otherwise (caller applies the ``_no_pii`` suffix to
        ``persona_id``).

        UNIQUE(job_id, email_hash) ``IntegrityError`` is caught silently —
        the existing row wins (idempotency per spec.md REQ-020 AC-020.6).
        """
        if not plaintext:
            return False
        if encryption_key is None:
            errors.append(
                f"encryption key missing — identity_map row skipped for hash={email_hash[:8]}"
            )
            return False

        try:
            cipher = encrypt_email(plaintext, encryption_key)
        except EncryptionKeyMissingError as e:
            errors.append(
                f"encryption key invalid: {e!s} — identity_map row skipped for hash={email_hash[:8]}"
            )
            return False

        row = IdentityMap(
            job_id=job_id,
            email_hash=email_hash,
            encrypted_email=cipher.decode("ascii"),
            persona_id=persona_id,
        )
        try:
            db.add(row)
            db.flush()
            return True
        except IntegrityError:
            db.rollback()
            return True  # existing row wins — still "ok"

    @staticmethod
    def _make_llm_client() -> Any:
        """Lazy import the LLMClient to avoid circulars at module import time."""
        from app.llm.client import LLMClient

        return LLMClient()


__all__ = [
    "SOURCE_MODULES",
    "PersonDossier",
    "PersonDossierModule",
]


# Module-level helper class — used as a sentinel so the type-checker
# distinguishes a sibling-still-running skip from a normal early-return.


@dataclass(frozen=True)
class _SkipSignal:
    """Marker returned by `_load_sibling_state` to signal a clean skip."""

    error: str

    def as_module_output(self, module_name: str, start: float) -> ModuleOutput:
        """Build the empty ModuleOutput for the skip path."""
        return ModuleOutput(
            module=module_name,
            findings=[],
            duration_seconds=time.time() - start,
            errors=[self.error],
        )
