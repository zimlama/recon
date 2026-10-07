"""Audit subsystem: middleware for logging all user actions."""

from app.audit.middleware import AuditLogMiddleware

__all__ = ["AuditLogMiddleware"]
