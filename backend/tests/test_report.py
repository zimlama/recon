"""Tests for the report subsystem (app.report).

Covers:
- app/report/__init__.py  — re-exports the three public names
- app/report/css_style.py — load_css() reads brand-kit CSS or returns ""
- app/report/markdown_gen.py — MarkdownReportGenerator end-to-end
- app/report/pdf_gen.py — PDFGenerator.convert() subprocess orchestration

The PDF generator shells out to ``npx md-to-pdf``. We don't run a real
Node toolchain in tests; instead we mock ``asyncio.create_subprocess_exec``
to drive the returncode/timeout/error branches deterministically.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.models import (
    AIValidation,
    Finding,
    FindingType,
    Job,
    JobStatus,
    ModuleRun,
    ModuleStatus,
    ModuleTier,
    _now,
)
from app.report import MarkdownReportGenerator, PDFGenerator, load_css
from app.report.css_style import load_css as load_css_direct
from app.report.markdown_gen import MarkdownReportGenerator as MRG_direct
from app.report.pdf_gen import PDFGenerator as PDFG_direct

# ---------------------------------------------------------------------------
# app/report/__init__.py — re-exports
# ---------------------------------------------------------------------------


def test_report_package_exposes_three_names() -> None:
    """The report package re-exports MarkdownReportGenerator, PDFGenerator, load_css."""
    from app.report import __all__

    assert "MarkdownReportGenerator" in __all__
    assert "PDFGenerator" in __all__
    assert "load_css" in __all__


def test_report_package_reexports_resolve_to_same_objects() -> None:
    """Re-exported names point to the same class/function as direct imports."""
    assert MarkdownReportGenerator is MRG_direct
    assert PDFGenerator is PDFG_direct
    assert load_css is load_css_direct


# ---------------------------------------------------------------------------
# app/report/css_style.py — load_css
# ---------------------------------------------------------------------------


def test_load_css_returns_empty_when_brand_kit_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the brand-kit CSS file does not exist, load_css returns ''."""
    # Point _BRAND_KIT_CSS at a path we know doesn't exist.
    from app.report import css_style

    fake = tmp_path / "does_not_exist.css"
    monkeypatch.setattr(css_style, "_BRAND_KIT_CSS", fake)

    assert load_css() == ""


def test_load_css_returns_brand_kit_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the brand-kit CSS exists, its contents are returned verbatim."""
    from app.report import css_style

    css_file = tmp_path / "report.css"
    css_file.write_text("body { color: red; }", encoding="utf-8")
    monkeypatch.setattr(css_style, "_BRAND_KIT_CSS", css_file)

    assert load_css() == "body { color: red; }"


# ---------------------------------------------------------------------------
# app/report/markdown_gen.py — MarkdownReportGenerator
# ---------------------------------------------------------------------------


def _make_completed_job(
    db: Session, target: str = "example.com"
) -> Job:
    """Insert a completed Job with one ModuleRun + one Finding."""
    job = Job(
        target=target,
        target_type="domain",
        status=JobStatus.COMPLETED,
        selected_modules=["whois_rdap"],
        user_consent=True,
        typed_confirmation=target,
        consent_modal_version="v1",
        consent_timestamp=_now(),
        started_at=_now(),
        completed_at=_now(),
        duration_seconds=10.0,
    )
    db.add(job)
    db.flush()

    mr = ModuleRun(
        job_id=job.id,
        module_name="whois_rdap",
        module_tier=ModuleTier.TIER_1,
        status=ModuleStatus.COMPLETED,
        findings_count=1,
        duration_seconds=3.0,
    )
    db.add(mr)
    db.flush()

    finding = Finding(
        module_run_id=mr.id,
        type=FindingType.SUBDOMAIN,
        value="api.example.com",
        source="crtsh",
        confidence=0.9,
    )
    db.add(finding)

    validation = AIValidation(
        module_run_id=mr.id,
        decision={"verdicts": []},
        summary="Looks fine.",
        confidence=0.8,
        recommended_action="CONTINUE",
        recommended_next_modules=[],
    )
    db.add(validation)
    db.commit()
    db.refresh(job)
    return job


def test_markdown_report_generate_writes_file(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """generate() writes the markdown report to REPORTS_DIR and returns the path."""
    job = _make_completed_job(db)

    # Redirect REPORTS_DIR to a fresh tmp dir so we don't pollute ./data
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "REPORTS_DIR", str(reports_dir))

    gen = MarkdownReportGenerator(db, job)
    # Run async generate()
    out = asyncio.run(gen.generate())

    assert out.exists()
    assert out.suffix == ".md"
    contents = out.read_text(encoding="utf-8")
    # Frontmatter, title, executive summary, and annex sections all present
    assert "title:" in contents
    assert "Reconocimiento Pasivo" in contents
    assert "Resumen Ejecutivo" in contents
    assert "Metodología" in contents
    assert "Anexos" in contents
    assert "api.example.com" in contents  # finding value surfaced


def test_markdown_report_executive_summary_counts(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Executive summary tallies modules + findings correctly."""
    job = _make_completed_job(db)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "REPORTS_DIR", str(reports_dir))

    out = asyncio.run(MarkdownReportGenerator(db, job).generate())
    contents = out.read_text(encoding="utf-8")

    # 1 module, completed, 1 finding
    assert "1 módulos" in contents or "1 de los cuales" in contents
    assert "1 hallazgos" in contents


def test_markdown_report_includes_ai_insights_when_validation_present(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """include_ai=True surfaces the AI summary line per module."""
    job = _make_completed_job(db)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "REPORTS_DIR", str(reports_dir))

    out = asyncio.run(
        MarkdownReportGenerator(db, job).generate(include_ai_insights=True)
    )
    contents = out.read_text(encoding="utf-8")
    assert "AI Summary" in contents
    assert "Looks fine." in contents


def test_markdown_report_omits_ai_when_disabled(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """include_ai=False omits the AI section entirely."""
    job = _make_completed_job(db)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "REPORTS_DIR", str(reports_dir))

    out = asyncio.run(
        MarkdownReportGenerator(db, job).generate(include_ai_insights=False)
    )
    contents = out.read_text(encoding="utf-8")
    assert "AI Insights" not in contents


def test_markdown_report_omits_annex_when_disabled(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """include_annex=False omits the Annex section entirely."""
    job = _make_completed_job(db)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "REPORTS_DIR", str(reports_dir))

    out = asyncio.run(MarkdownReportGenerator(db, job).generate(include_annex=False))
    contents = out.read_text(encoding="utf-8")
    assert "Anexos" not in contents


def test_markdown_report_handles_no_module_runs(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A job with zero module runs still generates a valid report."""
    job = Job(
        target="empty.com",
        target_type="domain",
        status=JobStatus.COMPLETED,
        selected_modules=[],
        user_consent=True,
        typed_confirmation="empty.com",
        consent_modal_version="v1",
        consent_timestamp=_now(),
        started_at=_now(),
        completed_at=_now(),
        duration_seconds=0.0,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "REPORTS_DIR", str(reports_dir))

    out = asyncio.run(MarkdownReportGenerator(db, job).generate())
    contents = out.read_text(encoding="utf-8")
    assert "0 módulos" in contents
    assert "0 hallazgos" in contents


def test_markdown_report_limits_finding_table_to_50(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a module has >50 findings, the table is truncated."""
    job = Job(
        target="big.com",
        target_type="domain",
        status=JobStatus.COMPLETED,
        selected_modules=["whois_rdap"],
        user_consent=True,
        typed_confirmation="big.com",
        consent_modal_version="v1",
        consent_timestamp=_now(),
        started_at=_now(),
        completed_at=_now(),
        duration_seconds=10.0,
    )
    db.add(job)
    db.flush()
    mr = ModuleRun(
        job_id=job.id,
        module_name="whois_rdap",
        module_tier=ModuleTier.TIER_1,
        status=ModuleStatus.COMPLETED,
        findings_count=60,
        duration_seconds=5.0,
    )
    db.add(mr)
    db.flush()
    for i in range(60):
        db.add(
            Finding(
                module_run_id=mr.id,
                type=FindingType.SUBDOMAIN,
                value=f"host{i}.big.com",
                source="x",
                confidence=0.5,
            )
        )
    db.commit()
    db.refresh(job)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "REPORTS_DIR", str(reports_dir))

    out = asyncio.run(MarkdownReportGenerator(db, job).generate(include_ai_insights=False))
    contents = out.read_text(encoding="utf-8")
    assert "y 10 más" in contents  # 60 - 50 = 10 truncated


# ---------------------------------------------------------------------------
# app/report/pdf_gen.py — PDFGenerator
# ---------------------------------------------------------------------------


def _touch(path: Path) -> Path:
    """Create an empty file at ``path`` and return it."""
    path.write_text("placeholder md", encoding="utf-8")
    return path


def test_pdf_convert_returns_none_when_md_missing(tmp_path: Path) -> None:
    """If the markdown file doesn't exist, convert() returns None."""
    gen = PDFGenerator()
    missing = tmp_path / "nope.md"

    out = asyncio.run(gen.convert(missing))
    assert out is None


def test_pdf_convert_returns_none_when_npx_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If shutil.which('npx') returns None, convert() returns None."""
    md = _touch(tmp_path / "r.md")

    gen = PDFGenerator()
    with patch("app.report.pdf_gen.shutil.which", return_value=None):
        out = asyncio.run(gen.convert(md))

    assert out is None


def _make_subprocess_mock(returncode: int, side_effect_timeout: bool = False) -> MagicMock:
    """Build a fake subprocess whose communicate() returns (b'', b'') and returncode."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.pid = 12345
    if side_effect_timeout:
        # First call: wait_for(communicate()) raises TimeoutError; second call (wait()) returns
        proc.communicate = AsyncMock(side_effect=TimeoutError)
        proc.wait = AsyncMock(return_value=None)
    else:
        proc.communicate = AsyncMock(return_value=(b"", b""))
    proc.kill = MagicMock()
    return proc


def test_pdf_convert_success_returns_pdf_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Happy path: subprocess exits 0, PDF file appears at md.with_suffix('.pdf')."""
    md = _touch(tmp_path / "r.md")
    pdf = md.with_suffix(".pdf")
    pdf.write_bytes(b"%PDF-1.4\n%fake")  # pre-create the PDF as md-to-pdf would

    proc = _make_subprocess_mock(returncode=0)
    with patch("app.report.pdf_gen.shutil.which", return_value="/usr/bin/npx"), \
         patch("app.report.pdf_gen.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)), \
         patch("app.report.pdf_gen.load_css", return_value=""):
        out = asyncio.run(PDFGenerator().convert(md))

    assert out == pdf
    assert pdf.exists()


def test_pdf_convert_creates_css_sidecar_when_brand_kit_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When load_css() returns content, a _report.css sidecar is created + cleaned up."""
    md = _touch(tmp_path / "r.md")
    pdf = md.with_suffix(".pdf")
    pdf.write_bytes(b"%PDF-1.4\n%fake")

    proc = _make_subprocess_mock(returncode=0)
    css_sidecar = md.parent / "_report.css"

    with patch("app.report.pdf_gen.shutil.which", return_value="/usr/bin/npx"), \
         patch("app.report.pdf_gen.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)), \
         patch("app.report.pdf_gen.load_css", return_value="body { color: red; }"):
        out = asyncio.run(PDFGenerator().convert(md))

    assert out == pdf
    assert not css_sidecar.exists()  # cleaned up in finally


def test_pdf_convert_nonzero_returncode_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the subprocess exits non-zero, convert() returns None."""
    md = _touch(tmp_path / "r.md")
    proc = _make_subprocess_mock(returncode=1)

    with patch("app.report.pdf_gen.shutil.which", return_value="/usr/bin/npx"), \
         patch("app.report.pdf_gen.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)), \
         patch("app.report.pdf_gen.load_css", return_value=""):
        out = asyncio.run(PDFGenerator().convert(md))

    assert out is None


def test_pdf_convert_timeout_kills_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the subprocess exceeds the 120s timeout, the process group is killed."""
    md = _touch(tmp_path / "r.md")
    proc = _make_subprocess_mock(returncode=0, side_effect_timeout=True)

    with patch("app.report.pdf_gen.shutil.which", return_value="/usr/bin/npx"), \
         patch("app.report.pdf_gen.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)), \
         patch("app.report.pdf_gen.load_css", return_value=""), \
         patch("app.report.pdf_gen.os.killpg") as mock_killpg:
        out = asyncio.run(PDFGenerator().convert(md))

    assert out is None
    # os.killpg(SIGTERM) was called at least once
    assert mock_killpg.call_count >= 1


def test_pdf_convert_subprocess_exception_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If create_subprocess_exec itself raises, convert() returns None."""
    md = _touch(tmp_path / "r.md")

    with patch("app.report.pdf_gen.shutil.which", return_value="/usr/bin/npx"), \
         patch("app.report.pdf_gen.asyncio.create_subprocess_exec", new=AsyncMock(side_effect=OSError("boom"))), \
         patch("app.report.pdf_gen.load_css", return_value=""):
        out = asyncio.run(PDFGenerator().convert(md))

    assert out is None


def test_pdf_convert_pdf_missing_after_success_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If subprocess exits 0 but no PDF appears, convert() returns None."""
    md = _touch(tmp_path / "r.md")
    proc = _make_subprocess_mock(returncode=0)
    # Note: we DON'T create the .pdf file

    with patch("app.report.pdf_gen.shutil.which", return_value="/usr/bin/npx"), \
         patch("app.report.pdf_gen.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)), \
         patch("app.report.pdf_gen.load_css", return_value=""):
        out = asyncio.run(PDFGenerator().convert(md))

    assert out is None


def test_pdf_generator_default_timeout() -> None:
    """PDFGenerator's default timeout is 120 seconds."""
    assert PDFGenerator().timeout == 120
