# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Logging utilities — KwargsLoggerAdapter for structured logging.

The recon codebase uses structured logging throughout:
    logger.info("handoff_imported", path=str(p), schema_version=v)

But stdlib `logging.Logger.info()` only accepts `(msg, *args, **kwargs)`
where kwargs are limited to `extra`, `exc_info`, `stack_info`, `stacklevel`.
Passing arbitrary kwargs (e.g. `path=`, `schema_version=`) raises
mypy `[call-arg]` errors.

This module provides `KwargsLoggerAdapter` which intercepts arbitrary
kwargs and merges them into the `extra` dict. This preserves the
existing call sites while satisfying strict mypy.

Usage:
    from app.logging import get_logger

    logger = get_logger(__name__)
    logger.info("handoff_imported", path=str(p), schema_version=v)
    # Renders as: "handoff_imported" with extra={"path": ..., "schema_version": ...}
"""
from __future__ import annotations

import logging
from typing import Any


# Standard logging kwargs that are NOT part of the structured payload.
# Any kwarg NOT in this set is treated as a structured-logging field
# and merged into the `extra` dict passed to the underlying logger.
_RESERVED_KWARGS = frozenset({"extra", "exc_info", "stack_info", "stacklevel"})


class KwargsLoggerAdapter(logging.LoggerAdapter):  # type: ignore[type-arg]
    """LoggerAdapter that accepts arbitrary kwargs as structured fields.

    Behaves like stdlib `logging.LoggerAdapter` but with a `process()`
    that pulls custom kwargs out of the kwarg dict and merges them into
    `extra`. This is the mypy-friendly way to do structured logging
    without invasive changes to call sites.
    """

    def process(  # type: ignore[override]
        self,
        msg: Any,
        kwargs: dict[str, Any],
    ) -> tuple[Any, dict[str, Any]]:
        """Merge custom kwargs into `extra`, keep reserved kwargs as-is."""
        extra = dict(kwargs.get("extra") or {})
        for key, value in kwargs.items():
            if key not in _RESERVED_KWARGS:
                extra[key] = value
        new_kwargs: dict[str, Any] = {
            k: v for k, v in kwargs.items() if k in _RESERVED_KWARGS
        }
        if extra:
            new_kwargs["extra"] = extra
        return msg, new_kwargs


def get_logger(name: str) -> KwargsLoggerAdapter:
    """Return a KwargsLoggerAdapter wrapping the named logger.

    Drop-in replacement for `logging.getLogger(name)` in the recon
    codebase. Every call site should use this to get structured-logging
    support and mypy `[call-arg]` compliance.
    """
    return KwargsLoggerAdapter(logging.getLogger(name), {})
