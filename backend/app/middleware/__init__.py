# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""FastAPI middlewares for the recon app.

Currently ships:

- :class:`~app.middleware.roe.RoEMiddleware` — gates protected POST
  endpoints on the existence of an active Rules-of-Engagement envelope
  (PR 1). Disabled by default; enable with ``ROE_ENABLED=true``.
"""
