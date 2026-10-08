"""Email pseudonymization + Fernet encryption helpers (PR 4).

This module is the **privacy boundary** for raw email handling. Plaintext
emails are scoped to a single call chain:

    _resolve_plaintext_email(sources) → encrypt_email() → IdentityMap.encrypted_email

The plaintext NEVER appears in:
  - logs (`logger.*` calls),
  - the LLM prompt payload (only `email_hash` crosses the wire),
  - `Finding.finding_metadata` (Pydantic schema forbids `extra` fields),
  - the handoff export.

`hash_email()` is deterministic (no salt) so the same email always
hashes to the same pseudonym — that's how `person_dossier` groups
findings across modules for the same identity.

`encrypt_email()` uses Fernet (AES-128-CBC + HMAC-SHA256). The key is
sourced from the `PERSON_DOSSIER_ENCRYPTION_KEY` env var. Fernet does
NOT support key rotation natively — single-key v1 scope per spec.md
REQ-020 §2 (Open Question Q5).
"""

from __future__ import annotations

import hashlib

from cryptography.fernet import Fernet, InvalidToken


class EncryptionKeyMissingError(Exception):
    """Raised when the encryption key is unset, invalid, or wrong shape.

    Per spec.md A-020.e — the caller (person_dossier) catches this,
    logs a warning, and skips the identity_map row. The dossier is
    still emitted; only the encrypted backup is missing.
    """


def hash_email(email: str) -> str:
    """Return SHA-256 hex of the lowercased, stripped email.

    Deterministic (no salt) so the same email always produces the same
    pseudonym. This is what makes cross-module grouping possible:
    `email_harvesting`, `socmint`, `breach_data`, and `employee_osint`
    can all hash the same email and land in the same bucket.

    Args:
        email: Raw email string. May have mixed case and whitespace.

    Returns:
        64-char lowercase hex SHA-256 digest.
    """
    normalized = email.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def encrypt_email(email: str, key: bytes | None) -> bytes:
    """Encrypt `email` with Fernet (AES-128-CBC + HMAC-SHA256).

    Args:
        email: Plaintext email string. Bytes-safe via UTF-8 encoding.
        key: Fernet key (32 url-safe base64-encoded bytes). If ``None`` or
            malformed, raise ``EncryptionKeyMissingError``.

    Returns:
        Fernet ciphertext (bytes) — starts with the `gAAAAA` prefix.

    Raises:
        EncryptionKeyMissingError: key is ``None`` or not a valid Fernet key.
    """
    if key is None:
        raise EncryptionKeyMissingError(
            "PERSON_DOSSIER_ENCRYPTION_KEY is unset — cannot encrypt raw email"
        )
    try:
        fernet = Fernet(key)
    except (ValueError, TypeError) as e:
        # Fernet raises ValueError for malformed keys. We translate to
        # EncryptionKeyMissingError so callers have a single exception
        # type to catch (per spec.md A-020.e).
        raise EncryptionKeyMissingError(
            f"PERSON_DOSSIER_ENCRYPTION_KEY is malformed: {e!s}"
        ) from e
    return fernet.encrypt(email.encode("utf-8"))


__all__ = [
    "EncryptionKeyMissingError",
    "encrypt_email",
    "hash_email",
]


# Re-export so callers can `from app.utils.encryption import InvalidToken`
# without importing cryptography directly.
InvalidToken = InvalidToken