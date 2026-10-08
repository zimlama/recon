# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Request ID middleware — propagates an X-Request-ID per request.

Audit finding R4-H4: the v0.2.0 release had no correlation ID
machinery. When a RoE 403 or any other error landed on the dashboard,
the only handle in logs was a timestamp + path; tracking down the
specific request required manual correlation.

The middleware:

- Reads ``X-Request-ID`` from the request (clients/middleware can
  propagate their own). If absent, generates a UUID4.
- Stores it on ``request.state.request_id``.
- Echoes it back via the ``X-Request-ID`` response header so the
  caller can correlate logs.

Wired in ``main.create_app()`` BEFORE RoEMiddleware / AuditLog so the
ID is on every request that flows through the chain.
"""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a UUID to every request and echo it in the response.

    Existing ``X-Request-ID`` headers are honored (clients and proxies
    can supply their own). When absent, a fresh UUID4 is generated.
    """

    def __init__(self, app: ASGIApp, header_name: str = "X-Request-ID") -> None:
        super().__init__(app)
        self._header_name = header_name

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        # Honor the caller's ID when present; otherwise mint a UUID4.
        rid = request.headers.get(self._header_name) or str(uuid.uuid4())
        # Stash on request.state so handlers / loggers / DB rows can
        # pick it up.
        request.state.request_id = rid
        # Run the rest of the stack.
        response = await call_next(request)
        # Echo back so the caller can grep logs for the same string.
        response.headers[self._header_name] = rid
        return response


__all__ = ["RequestIdMiddleware"]
