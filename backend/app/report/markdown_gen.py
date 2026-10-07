"""Markdown report generator — Job → Markdown."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AIValidation, Job, ModuleRun
from app.modules.base import Finding

logger = logging.getLogger(__name__)
settings = get_settings()


class MarkdownReportGenerator:
    """Generates a markdown report for a completed recon job."""

    def __init__(self, db: Session, job: Job) -> None:
        self.db = db
        self.job = job

    async def generate(
        self,
        include_raw_findings: bool = True,
        include_ai_insights: bool = True,
        include_annex: bool = True,
    ) -> Path:
        """Build the markdown report and write to disk.

        Returns the path to the generated .md file.
        """
        md = self._build_markdown(include_raw_findings, include_ai_insights, include_annex)

        reports_dir = Path(settings.REPORTS_DIR)
        reports_dir.mkdir(parents=True, exist_ok=True)
        output_path = reports_dir / f"recon-{self.job.target}-{self.job.id[:8]}.md"
        output_path.write_text(md, encoding="utf-8")

        logger.info("report_generated", path=str(output_path), target=self.job.target)
        return output_path

    def _build_markdown(
        self,
        include_raw: bool,
        include_ai: bool,
        include_annex: bool,
    ) -> str:
        """Build the full markdown content."""
        sections: list[str] = []

        # Frontmatter
        sections.append(self._frontmatter())
        sections.append("")

        # Title + cover
        sections.extend(self._cover())
        sections.append("")

        # Executive summary
        sections.extend(self._executive_summary())
        sections.append("")

        # Methodology
        sections.extend(self._methodology())
        sections.append("")

        # Findings by module
        sections.extend(self._findings_by_module(include_raw, include_ai))
        sections.append("")

        # AI insights
        if include_ai:
            sections.extend(self._ai_insights())
            sections.append("")

        # Annex
        if include_annex:
            sections.extend(self._annex())
            sections.append("")

        return "\n".join(sections)

    def _frontmatter(self) -> str:
        return f"""---
title: "Reconocimiento Pasivo — {self.job.target}"
target: "{self.job.target}"
date: "{datetime.utcnow().strftime('%Y-%m-%d')}"
job_id: "{self.job.id}"
phase: "01-recon-osint"
ai_validated: true
classification: "CONFIDENTIAL"
generator: "zimlama/recon v0.1.0"
---"""

    def _cover(self) -> list[str]:
        return [
            f"# Reconocimiento Pasivo — Fase 1",
            "",
            f"**Target:** `{self.job.target}`  ",
            f"**Job ID:** `{self.job.id}`  ",
            f"**Fecha:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Phase:** 01-recon-osint (passive)  ",
            "",
            "---",
            "",
        ]

    def _executive_summary(self) -> list[str]:
        module_runs = self.db.query(ModuleRun).filter(ModuleRun.job_id == self.job.id).all()
        total_findings = sum(mr.findings_count for mr in module_runs)
        total_modules = len(module_runs)
        successful = sum(1 for mr in module_runs if mr.status.value == "completed")

        return [
            "## Resumen Ejecutivo",
            "",
            f"Este reporte presenta los resultados de la fase de reconocimiento pasivo (Fase 1) sobre el dominio `{self.job.target}`. Se ejecutaron {total_modules} módulos, {successful} de los cuales completaron exitosamente, descubriendo un total de {total_findings} hallazgos.",
            "",
            f"- **Módulos ejecutados:** {total_modules}",
            f"- **Módulos exitosos:** {successful}",
            f"- **Hallazgos totales:** {total_findings}",
            f"- **Duración:** {self.job.duration_seconds or 0:.0f} segundos",
            "",
            "### Top 5 Hallazgos por Prioridad",
            "",
            "_Generado automáticamente por AI al cierre del job._",
            "",
        ]

    def _methodology(self) -> list[str]:
        return [
            "## Metodología",
            "",
            "El reconocimiento pasivo se realizó siguiendo las técnicas definidas por MITRE ATT&CK (T1589, T1590, T1591, T1592, T1593, T1595, T1596) y OWASP Testing Guide v4.2.",
            "",
            "**Fuentes consultadas (Tier 1, siempre activas):**",
            "",
            "- WHOIS / RDAP (registro de dominio)",
            "- DNS enumeration (A, AAAA, NS, MX, TXT, CNAME, SOA, SRV)",
            "- Subdomain enumeration (subfinder, crt.sh, amass)",
            "- Certificate Transparency (crt.sh, Censys)",
            "- Wayback Machine (gau, waybackurls, CDX API)",
            "- Email harvesting (Hunter.io, PGP, breach data k-anon)",
            "",
            "Cada hallazgo fue validado con **MiniMax M3** para filtrar falsos positivos, asignar prioridad (HIGH/MEDIUM/LOW) y sugerir acciones para la siguiente fase.",
            "",
        ]

    def _findings_by_module(self, include_raw: bool, include_ai: bool) -> list[str]:
        module_runs = self.db.query(ModuleRun).filter(ModuleRun.job_id == self.job.id).all()
        sections: list[str] = ["## Hallazgos por Módulo", ""]

        for i, mr in enumerate(module_runs, 1):
            sections.append(f"### {i}. {mr.module_name}")
            sections.append("")
            sections.append(f"- **Tier:** {mr.module_tier.value}")
            sections.append(f"- **Status:** {mr.status.value}")
            sections.append(f"- **Hallazgos:** {mr.findings_count}")
            sections.append(f"- **Duración:** {mr.duration_seconds or 0:.1f}s")
            sections.append("")

            if not mr.findings:
                sections.append("_No se encontraron hallazgos._")
                sections.append("")
                continue

            if include_raw:
                # Table of findings
                sections.append("| Valor | Tipo | Fuente | Confianza |")
                sections.append("|-------|------|--------|-----------|")
                for f in mr.findings[:50]:  # limit to first 50
                    value = f.value.replace("|", "\\|")[:80]
                    sections.append(
                        f"| `{value}` | {f.type.value} | {f.source} | {f.confidence:.2f} |"
                    )
                if len(mr.findings) > 50:
                    sections.append(f"| _...y {len(mr.findings) - 50} más_ | | | |")
                sections.append("")

            if include_ai and mr.validation:
                v = mr.validation
                sections.append(f"**AI Summary:** {v.summary}")
                sections.append(f"**AI Confidence:** {v.confidence:.2f}")
                sections.append(f"**Recommended Action:** {v.recommended_action}")
                if v.recommended_next_modules:
                    sections.append(
                        f"**Next Modules:** {', '.join(v.recommended_next_modules)}"
                    )
                sections.append("")

        return sections

    def _ai_insights(self) -> list[str]:
        module_runs = (
            self.db.query(ModuleRun)
            .filter(ModuleRun.job_id == self.job.id)
            .all()
        )
        sections: list[str] = ["## AI Insights (MiniMax M3)", ""]

        any_validations = False
        for mr in module_runs:
            if not mr.validation:
                continue
            any_validations = True
            v = mr.validation
            sections.append(f"### {mr.module_name}")
            sections.append("")
            sections.append(f"> {v.summary}")
            sections.append("")

        if not any_validations:
            sections.append("_No AI validations were run for this job._")
            sections.append("")

        return sections

    def _annex(self) -> list[str]:
        return [
            "## Anexos",
            "",
            "### A. Comandos ejecutados",
            "",
            "Los comandos específicos ejecutados por cada módulo se almacenan en los logs del backend (`./data/audit/`).",
            "",
            "### B. Artefactos crudos",
            "",
            "Los outputs crudos de cada herramienta (subfinder, amass, etc.) se almacenan en `./data/artifacts/`.",
            "",
            "### C. Handoff packet",
            "",
            f"Un handoff packet vendor-neutral ha sido generado para este job y está disponible vía:",
            "",
            f"- REST: `GET /api/v1/jobs/{self.job.id}/handoff`",
            f"- Download: `GET /api/v1/jobs/{self.job.id}/handoff/download`",
            "",
            "Este handoff puede ser consumido por herramientas de Fase 2 (scanning activo) en otros proyectos.",
            "",
            "---",
            "",
            f"_Reporte generado por zimlama/recon v0.1.0 — {datetime.utcnow().isoformat()}Z_",
            "",
        ]


__all__ = ["MarkdownReportGenerator"]
