# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""RoE enforcement middleware for the FastAPI app.

Disabled by default. Enable by exporting `ROE_ENABLED=true` before the
process starts. When enabled, this middleware rejects POSTs to the
protected paths (`/api/v1/jobs*` by default) unless the target named in
the JSON body is covered by an active RoE with at least one un-revoked
sign-off — same rule the orchestrator uses in-process.

Design notes:

- **Env flag at construction**: We read `ROE_ENABLED` once in `__init__`
  rather than per-request. Operators flip it by restarting the process,
  which keeps the rule predictable and avoids per-request syscalls.

- **Body access**: We call `await request.body()` exactly once. Starlette
  caches the bytes internally and downstream calls to `request.body()`
  return the same cached payload, so the FastAPI route handler can still
  parse the JSON normally. We do NOT swap `request._receive` — patching
  the receive callable from inside `BaseHTTPMiddleware` breaks Starlette's
  internal `_CachedRequest` and triggers
  `RuntimeError: Unexpected message received: http.request`.

- **Fail-closed on bad JSON**: A POST with a malformed body returns 400
  rather than 403. The RoE gate never makes a "yes" decision on data
  it couldn't parse — that would be a silent foot-gun.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable

from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

from app.models import ScopeType
from app.orchestrator.roe import RoEValidator

_DEFAULT_PROTECTED_PATHS: tuple[str, ...] = (
    "/api/v1/jobs",  # POST
    "/api/v1/jobs/",  # POST cancel / DELETE
)


class RoEMiddleware(BaseHTTPMiddleware):
    """Enforces active-RoE coverage on protected POST endpoints."""

    def __init__(
        self,
        app: ASGIApp,
        session_factory: Callable[[], Session],
        protected_paths: Iterable[str] | None = None,
    ) -> None:
        super().__init__(app)
        self._session_factory = session_factory
        self._enabled = os.getenv("ROE_ENABLED", "false").lower() == "true"
        self._protected_paths: list[str] = list(
            protected_paths if protected_paths is not None else _DEFAULT_PROTECTED_PATHS
        )

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        # Fast path: disabled OR non-POST OR not on the protected list.
        # We do this BEFORE touching the body so unaffected requests stay
        # cheap.
        if not self._enabled or request.method != "POST":
            return await call_next(request)
        if not any(
            request.url.path.startswith(p) for p in self._protected_paths
        ):
            return await call_next(request)

        # Starlette caches `request.body()` internally, so a single read
        # here is enough — downstream handlers calling `request.body()`
        # again receive the same bytes.
        body = await request.body()

        target, payload, parse_error = _extract_target(body)
        if parse_error is not None:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_body",
                    "detail": parse_error,
                },
            )
        if target is None or target == "":
            return JSONResponse(
                status_code=400,
                content={
                    "error": "missing_target",
                    "detail": "Request body must include a non-empty 'target'.",
                },
            )

        scope_type = _coerce_scope_type(payload)
        validator = RoEValidator(self._session_factory)
        authorized, reason, _ = validator.is_authorized(
            target=target, scope_type=scope_type
        )
        if not authorized:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "roe_not_authorized",
                    "detail": reason or "No active RoE for this target.",
                },
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_target(body: bytes) -> tuple[str | None, dict[str, object], str | None]:
    """Pull `target` out of the JSON body.

    Returns ``(target, payload, parse_error)``. On JSON parse failure
    ``parse_error`` is set; on success ``payload`` is the parsed dict
    (empty if the body was empty). Returns ``(None, {}, None)`` when
    ``target`` is absent or empty.
    """
    if not body:
        return None, {}, None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        return None, {}, f"Invalid JSON body: {exc.msg}"
    if not isinstance(payload, dict):
        return None, {}, "Request body must be a JSON object."
    raw = payload.get("target")
    if not isinstance(raw, str):
        return None, payload, None
    return raw, payload, None


def _coerce_scope_type(payload: dict[str, object]) -> ScopeType:
    """Map the optional ``scope_type`` field to a ``ScopeType`` enum.

    Defaults to ``DOMAIN``. Bad values fall back to ``DOMAIN`` too: a
    malformed ``scope_type`` must not become a denial-of-service trigger.
    """
    raw = payload.get("scope_type")
    if not isinstance(raw, str):
        return ScopeType.DOMAIN
    try:
        return ScopeType(raw)
    except ValueError:
        return ScopeType.DOMAIN


__all__ = ["RoEMiddleware"]
