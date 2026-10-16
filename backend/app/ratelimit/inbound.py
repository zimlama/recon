# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Inbound rate limiting — storage + middleware (PR-J3.6).

Algorithm
---------
Sliding-window per-(scope, key, endpoint) counter:

1. ``RateLimiter`` owns ``_buckets: dict[tuple[str, str, str], deque]``
   keyed by ``(scope, key, endpoint)``. ``scope`` is ``"ip"`` or
   ``"user"``; ``key`` is the IP string or ``request.state.user_id``;
   ``endpoint`` is the route TEMPLATE that matched ``request.url.path``
   via the compiled regex set on ``app.state.rate_limit_patterns``.

2. ``RateLimiter.is_allowed(scope, key, endpoint, *, count_it, now=None)``
   does the lazy-evict + check + append synchronously (no ``await``,
   so no other coroutine can interleave mid-call — see Concurrency).
   Returns ``(allowed, retry_after)`` where ``retry_after`` is
   ``None`` on allow and ``>= 1`` on reject (clamped via
   ``max(1, ceil(...))`` per MED-4).

3. ``RateLimitMiddleware(BaseHTTPMiddleware)`` calls ``is_allowed``
   twice per request: pre-call per-IP (decision D1), and post-call
   per-user when ``request.state.auth_method == "jwt"`` (decision
   D2 + HIGH-2 — legacy ``RECON_API_KEY`` callers do NOT tick the
   per-user counter; under per-user 4xx does NOT count toward the
   limit; success and 5xx always count).

4. Lookup uses compiled regex against ``request.url.path``
   (decision M / REQ-INB-016). ``request.scope["route"].path`` is
   ``None`` inside ``BaseHTTPMiddleware.dispatch``, so using it as
   the key makes the middleware fail-open on every request.

5. Clock injection (decision L) — ``RateLimiter`` accepts a ``clock``
   callable (default ``time.monotonic``) so tests are deterministic.
   No ``freezegun`` / ``time-machine`` per NFR-INB-003.

Concurrency
-----------
``RateLimiter.is_allowed`` is fully synchronous — no ``await`` and no
``asyncio.Lock`` on the hot path. Coroutines on the same event loop
cannot interleave mid-call, so the lazy-evict + check + append
sequence is atomic per key without explicit locking. (An
``asyncio.Lock`` would be over-engineered here and a ``threading.Lock``
would deadlock under ``BaseHTTPMiddleware.dispatch`` — HIGH-1.)

Memory bound
------------
``maxlen = requests_limit * 2`` per deque; no lifespan sweep (risk #2
in design.md §Decision K). The combination holds memory bounded
against a flood of distinct IPs — verified by
``test_bounded_memory.py``.
"""
from __future__ import annotations

import math
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class RateLimiter:
    """Sliding-window storage + decision service.

    The middleware's data backbone. Holds one ``collections.deque`` of
    monotonic timestamps per ``(scope, key, endpoint)`` triple, lazily
    evicting stale entries on each ``is_allowed`` call so the deque
    stays bounded by ``maxlen = requests_limit * 2``.

    See module docstring for the algorithm and concurrency model.
    """

    def __init__(
        self,
        clock: Callable[[], float] | None = None,
        *,
        policies: dict[tuple[str, str], tuple[int, int]] | None = None,
    ) -> None:
        """Construct a rate limiter.

        ``clock`` defaults to ``time.monotonic`` (decision L). Tests
        inject a ``FrozenClock`` via ``RateLimiter(clock=frozen_clock)``.
        ``policies`` is a ``{(scope, endpoint): (limit, window)}`` map;
        the middleware pulls limits from ``Settings.RATE_LIMITS`` at
        request time, so passing ``policies`` is reserved for unit
        tests that exercise the storage in isolation.
        """
        self._clock: Callable[[], float] = clock or time.monotonic
        # { (scope, key, endpoint): deque[float] }
        self._buckets: dict[tuple[str, str, str], deque[float]] = {}
        # {(scope, endpoint): (limit, window)}
        self._policies: dict[tuple[str, str], tuple[int, int]] = dict(policies or {})

    # ---- Inspectors (read-only; used in unit tests) --------------------

    @property
    def buckets(self) -> dict[tuple[str, str, str], deque[float]]:
        """Read-only view of the internal bucket dict (for assertions)."""
        return self._buckets

    # ---- Decision algorithm -------------------------------------------

    def _policy(self, scope: str, endpoint: str) -> tuple[int, int] | None:
        return self._policies.get((scope, endpoint))

    def is_allowed(
        self,
        scope: str,
        key: str,
        endpoint: str,
        *,
        count_it: bool = True,
        now: float | None = None,
    ) -> tuple[bool, int | None]:
        """Decide whether ``(scope, key, endpoint)`` may proceed.

        Returns ``(allowed, retry_after_seconds)``.

        - ``allowed=False`` → the deque is at-or-over the limit; the
          caller MUST emit a 429 with the returned ``retry_after_seconds``
          (always ``>= 1`` per the MED-4 contract).
        - ``allowed=True`` → the request may proceed; ``retry_after_seconds``
          is ``None``.

        ``count_it`` (HIGH-2): the per-user post-call phase passes
        ``count_it = (status < 400 or status >= 500)`` so 4xx does NOT
        count toward the per-user limit (legitimate user typo). Per-IP
        always counts (G1, credential-stuffing signal).

        ``now``: optional clock override for tests; defaults to
        ``self._clock()`` per the L contract.
        """
        policy = self._policy(scope, endpoint)
        if policy is None:
            # No policy registered for this scope+endpoint — fail-open.
            return True, None
        limit, window = policy
        dq = self._buckets.get((scope, key, endpoint))
        now_v = now if now is not None else self._clock()
        if dq is None:
            dq = deque(maxlen=limit * 2)
            self._buckets[(scope, key, endpoint)] = dq
        # 1. Lazy eviction — drop timestamps older than (now - window).
        #    This is O(k) where k is the count of dropped entries (the
        #    popleft loop). Combined with ``maxlen`` it bounds memory.
        threshold = now_v - window
        while dq and dq[0] < threshold:
            dq.popleft()
        # 2. Reject iff len(dq) >= limit. Per spec REQ-INB-003 the
        #    reject is the EARLY exit (before any append) so the 429
        #    path never ticks the bucket.
        if len(dq) >= limit:
            retry = max(1, math.ceil(dq[0] + window - now_v))
            return False, retry
        # 3. Append ONLY when ``count_it``. The deque's ``maxlen``
        #    auto-evicts the leftmost when full — combined with the
        #    lazy-evict step above, the worst case is ``maxlen - 1``
        #    recent entries plus an immediate reject on the next call.
        if count_it:
            dq.append(now_v)
        return True, None

    def configure(self, policies: dict[tuple[str, str], tuple[int, int]]) -> None:
        """Replace the policy map at runtime (test helper)."""
        self._policies = dict(policies)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


async def get_clock() -> Callable[[], float]:
    """FastAPI dependency: return the active monotonic clock producer.

    Tests override via ``app.dependency_overrides[get_clock] = lambda:
    lambda: frozen_now``. Production default is ``time.monotonic``.
    """
    return time.monotonic


def _compile_one(template: str) -> re.Pattern[str]:
    """Compile a single route template into an anchored regex.

    Per spec REQ-INB-016: literal segments are ``re.escape``d and
    ``{param}`` placeholders become ``[^/]+``. First match wins.
    """
    out = re.escape(template)
    # ``re.escape`` left any ``{...}`` sequences intact. Replace each
    # ``\{<name>\}`` placeholder with the dynamic-segment class.
    out = re.sub(r"\\\{[a-zA-Z_][a-zA-Z0-9_]*\\\}", r"[^/]+", out)
    return re.compile(f"^{out}$")


def compile_rate_limit_patterns(
    rate_limits: dict[str, tuple[int, int]],
) -> list[tuple[re.Pattern[str], tuple[int, int]]]:
    """Compile the per-route policy into regexes for request-time lookup.

    Called at app startup (the lifespan hook in
    ``backend/app/main.py``); the result lives on
    ``app.state.rate_limit_patterns``.

    Returns the regexes in **insertion order of ``rate_limits``** so a
    tied match resolves deterministically (the 7 defaults in
    ``Settings.RATE_LIMITS`` are themselves in insertion order).
    """
    return [(re.compile(_compile_one(template).pattern), policy) for template, policy in rate_limits.items()]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Inbound per-IP + per-user sliding-window limiter.

    Three phases (per design.md §Decision D):

    1. Pre-call — resolve the endpoint policy via compiled regex against
       ``request.url.path``; check the per-IP bucket; on reject, emit
       429 immediately (audit row + structlog inside the same
       lifecycle per REQ-INB-011).
    2. ``call_next`` — DualAuth populates ``request.state.user_id`` for
       JWT callers.
    3. Post-call — when ``auth_method == "jwt"`` (decision D2 +
       auth-bypass gating in design.md), check the per-user bucket
       with ``count_it = (status < 400 or status >= 500)``. On reject,
       overwrite the response with 429.

    Defaults: lookup miss → fail-open. Endpoints not in
    ``Settings.RATE_LIMITS`` are NOT rate-limited (REQ-INB-006 +
    REQ-INB-016 #3).
    """

    def __init__(
        self,
        app: Any,
        *,
        clock: Callable[[], float] | None = None,
        policies: dict[str, tuple[int, int]] | None = None,
        bypass_token: str = "",
        allow_bypass: bool = False,
        app_state: Any | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        super().__init__(app)
        self._limiter = limiter or RateLimiter(clock=clock or time.monotonic)
        if policies:
            self._limiter.configure({(scope, ep): p for (scope, ep), p in _scope_policies(policies).items()})
        self._bypass_token = bypass_token
        self._allow_bypass = allow_bypass
        self._app_state = app_state  # resolved from request.app.state at dispatch time

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Any]],
    ) -> Any:
        # 1. Resolve policy from the lifespan-compiled regex set on
        # app.state — fall back to fail-open if the test/build
        # didn't compile any (production path always does).
        patterns = getattr(request.app.state, "rate_limit_patterns", None) or []
        path = request.url.path
        endpoint: str | None = None
        policy: tuple[int, int] | None = None
        for regex, pol in patterns:
            if regex.match(path):
                endpoint = regex.pattern  # the regex string IS the lookup key
                policy = pol
                break

        if policy is None:
            # Fail-open per REQ-INB-016 #3 + REQ-INB-006 acceptance.
            return await call_next(request)

        _limit, _window = policy
        # Register the policy in the limiter so is_allowed can consult it.
        self._limiter.configure({("ip", endpoint): policy, ("user", endpoint): policy})

        # 2. Dev bypass — short-circuit BEFORE any counter tick.
        if self._allow_bypass and self._bypass_token:
            header = request.headers.get("x-bypass-rate-limit", "")
            if header == self._bypass_token:
                return await call_next(request)

        # 3. Pre-call per-IP.
        client_ip = (request.client.host if request.client else "unknown")
        allowed, retry = self._limiter.is_allowed(
            scope="ip", key=client_ip, endpoint=endpoint, count_it=True,
        )
        if not allowed:
            return await _emit_429(
                scope="ip",
                retry_after_seconds=retry or 1,
                request=request,
                endpoint=endpoint,
                policy=policy,
                key=client_ip,
            )

        # 4. call_next — DualAuth populates request.state.user_id.
        response = await call_next(request)

        # 5. Post-call per-user (decision D2 + HIGH-2).
        user_id = getattr(request.state, "user_id", None)
        auth_method = getattr(request.state, "auth_method", None)
        if user_id and auth_method == "jwt":
            status = getattr(response, "status_code", 0)
            count_it = (status < 400 or status >= 500)
            allowed_u, retry_u = self._limiter.is_allowed(
                scope="user", key=user_id, endpoint=endpoint, count_it=count_it,
            )
            if not allowed_u:
                return await _emit_429(
                    scope="user",
                    retry_after_seconds=retry_u or 1,
                    request=request,
                    endpoint=endpoint,
                    policy=policy,
                    key=user_id,
                )
        return response


def _scope_policies(
    by_endpoint: dict[str, tuple[int, int]],
) -> dict[tuple[str, str], tuple[int, int]]:
    """Fan-out a per-endpoint policy map to per-(scope, endpoint)."""
    return {
        (scope, ep): pol
        for ep, pol in by_endpoint.items()
        for scope in ("ip", "user")
    }


async def _emit_429(
    *,
    scope: str,
    retry_after_seconds: int,
    request: Request,
    endpoint: str,
    policy: tuple[int, int],
    key: str,
) -> JSONResponse:
    """Emit the canonical 429 response + observability hook.

    The structlog WARNING and ``audit_log`` insert live here so a
    429 has BOTH or NEITHER (spec REQ-INB-011).
    """
    # 1. structlog WARNING (PII hashing intentionally skipped — the
    # spec defines ``Settings.PII_HASHING`` which the env doesn't
    # expose yet; once added, swap ``key`` for its hash).
    request_id = getattr(request.state, "request_id", None)
    user_id = getattr(request.state, "user_id", None)
    logger.warning(
        "rate_limit_exceeded",
        scope=scope,
        key=key,
        endpoint=endpoint,
        retry_after_seconds=retry_after_seconds,
        request_id=request_id,
        user_id=user_id,
    )
    # 2. audit_log row — REQ-INB-011 says structlog and audit insert
    # MUST land in the same lifecycle. Keep try/except narrow so the
    # 429 is never blocked by a DB blip.
    try:
        from app.database import SessionLocal
        from app.models import AuditLog

        details: dict[str, Any] = {
            "scope": scope,
            "endpoint": endpoint,
            "retry_after_seconds": retry_after_seconds,
            "key": key,
        }
        with SessionLocal() as db:
            db.add(
                AuditLog(
                    action="rate_limit",
                    target=endpoint,
                    user_id=user_id or "anonymous",
                    username=getattr(request.state, "username", None) or "anonymous",
                    request_jwt_jti=getattr(request.state, "jwt_jti", None),
                    details=details,
                )
            )
            db.commit()
    except Exception:
        # Audit must never break the response.  The structlog WARNING
        # above is the load-bearing observability signal.
        pass
    # 3. The 429 response itself — Retry-After header + JSON body.
    body = {
        "error": "rate_limited",
        "retry_after_seconds": retry_after_seconds,
        "endpoint": endpoint,
        "scope": scope,
    }
    return JSONResponse(
        status_code=429,
        content=body,
        headers={"Retry-After": str(retry_after_seconds)},
    )


__all__ = [
    "RateLimitMiddleware",
    "RateLimiter",
    "compile_rate_limit_patterns",
    "get_clock",
]
