# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""FastAPI middlewares for the recon app.

Currently ships:

- :class:`~app.middleware.roe.RoEMiddleware` — gates protected POST
  endpoints on the existence of an active Rules-of-Engagement envelope
  (PR 1). Disabled by default; enable with ``ROE_ENABLED=true``.
- :class:`~app.middleware.request_id.RequestIdMiddleware` — attaches a
  UUID4 ``X-Request-ID`` to every request for log correlation
  (audit finding R4-H4).
"""

from app.middleware.request_id import RequestIdMiddleware
from app.middleware.roe import RoEMiddleware

__all__ = ["RequestIdMiddleware", "RoEMiddleware"]

