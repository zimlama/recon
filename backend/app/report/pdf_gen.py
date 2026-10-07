"""PDF generator — wraps md-to-pdf (Node) via subprocess."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
from pathlib import Path

from app.config import get_settings
from app.report.css_style import load_css

logger = logging.getLogger(__name__)
settings = get_settings()


class PDFGenerator:
    """Async wrapper around md-to-pdf (Node)."""

    def __init__(self) -> None:
        self.timeout = 120  # seconds

    async def convert(self, md_path: Path) -> Path | None:
        """Convert a markdown file to PDF using md-to-pdf.

        Returns the path to the generated PDF, or None if conversion failed.
        """
        if not md_path.exists():
            logger.error("md_file_not_found", path=str(md_path))
            return None

        pdf_path = md_path.with_suffix(".pdf")

        # Check if npx is available
        if not shutil.which("npx"):
            logger.warning("npx_not_found — PDF generation skipped. Install Node.js to enable.")
            return None

        # Check if md-to-pdf is available (try to use it)
        css_content = load_css()
        css_path = None
        if css_content:
            css_path = md_path.parent / "_report.css"
            css_path.write_text(css_content, encoding="utf-8")

        try:
            cmd = ["npx", "--yes", "md-to-pdf", str(md_path)]
            if css_path:
                cmd.extend(["--css", str(css_path)])

            logger.info("pdf_conversion_started", md=str(md_path))
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=md_path.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # child gets its own process group
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                # Kill the entire process group (npx spawns child processes),
                # not just the parent — prevents leaked Chromium/node workers.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                logger.error("pdf_conversion_timeout", md=str(md_path))
                return None

            if proc.returncode != 0:
                logger.error(
                    "pdf_conversion_failed",
                    returncode=proc.returncode,
                    stderr=stderr.decode("utf-8", errors="replace")[:500],
                )
                return None

            if pdf_path.exists():
                logger.info("pdf_generated", path=str(pdf_path))
                return pdf_path

            logger.error("pdf_not_created_after_success", path=str(pdf_path))
            return None
        except Exception as e:  # noqa: BLE001
            logger.exception("pdf_conversion_error", error=str(e))
            return None
        finally:
            if css_path and css_path.exists():
                try:
                    css_path.unlink()
                except OSError:
                    pass


__all__ = ["PDFGenerator"]
