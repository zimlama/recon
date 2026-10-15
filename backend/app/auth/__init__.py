"""sec-auth-jwt — per-user authentication (Issue #29, PR-J1).

Public surface is added incrementally across the chained PRs:

- J1: PasswordService, JwtKeyManager (this package's foundation).
- J2: RefreshService (rotation, family revoke, reuse detection).
- J3: AuthService facade + FastAPI router + dual-auth middleware.
- J4: CLI admin bootstrap (``recon users create-admin`` etc).
- J5: per-(user, endpoint) rate limiting + legacy-usage-stats endpoint.

Nothing is re-exported yet — sub-modules are imported directly.
"""