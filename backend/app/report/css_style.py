"""CSS loader — reads the brand-kit report.css for use with md-to-pdf."""

from __future__ import annotations

from pathlib import Path

# Path to the brand-kit CSS (relative to backend/)
_BRAND_KIT_CSS = Path(__file__).parent.parent.parent / "templates" / "brand-kit" / "report.css"


def load_css() -> str:
    """Load the report CSS from the brand-kit.

    Returns:
        The CSS content as a string. Returns empty string if file not found
        (development environments may not have the brand-kit).
    """
    if not _BRAND_KIT_CSS.exists():
        return ""
    return _BRAND_KIT_CSS.read_text(encoding="utf-8")


__all__ = ["load_css"]
