"""Tests for the email hashing + Fernet encryption helpers (PR 4).

Per spec.md REQ-020:
  - hash_email() — deterministic SHA-256 hex of the lowercased email
  - encrypt_email() — Fernet ciphertext (AES-128-CBC + HMAC-SHA256)
  - EncryptionKeyMissingError — raised when env var is unset or invalid

All functions live in `app/utils/encryption.py`.
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.utils.encryption import (
    EncryptionKeyMissingError,
    encrypt_email,
    hash_email,
)


# ---- hash_email() — deterministic SHA-256 hex ----


def test_hash_email_returns_64_char_hex() -> None:
    """hash_email() returns exactly 64 hex chars (SHA-256 length)."""
    h = hash_email("jane@example.com")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_email_lowercases_input() -> None:
    """hash_email() is case-insensitive (lower + strip before hashing).

    Per AC-020.1 — same hash for 'Jane@Example.com' and 'jane@example.com'.
    """
    assert hash_email("Jane@Example.com") == hash_email("jane@example.com")
    assert hash_email("JANE@EXAMPLE.COM") == hash_email("jane@example.com")


def test_hash_email_strips_whitespace() -> None:
    """hash_email() strips leading/trailing whitespace before hashing."""
    assert hash_email("  jane@example.com  ") == hash_email("jane@example.com")
    assert hash_email("\tjane@example.com\n") == hash_email("jane@example.com")


def test_hash_email_deterministic_fixed_vector() -> None:
    """hash_email() matches the canonical SHA-256 hex of the lowercased email.

    Per AC-020.2 — fixed test vector to catch regressions.
    """
    # hashlib is the ground truth — if our implementation differs, something
    # is wrong with lower/strip semantics or the encoding.
    expected = hashlib.sha256("a@b.c".encode("utf-8")).hexdigest()
    assert hash_email("a@b.c") == expected
    assert hash_email("A@B.C") == expected


def test_hash_email_distinct_inputs_distinct_outputs() -> None:
    """Distinct emails produce distinct hashes (no collisions)."""
    h1 = hash_email("alice@example.com")
    h2 = hash_email("bob@example.com")
    assert h1 != h2


def test_hash_email_no_salt() -> None:
    """hash_email() has no salt — it's deterministic for cross-job grouping.

    REQ-020 spec: 'No salt (deterministic for grouping)'.
    """
    h1 = hash_email("jane@example.com")
    h2 = hash_email("jane@example.com")
    assert h1 == h2


# ---- encrypt_email() — Fernet ciphertext ----


def test_encrypt_email_returns_fernet_token() -> None:
    """encrypt_email() returns a string starting with the Fernet prefix 'gAAAAA'."""
    key = Fernet.generate_key()
    cipher = encrypt_email("jane@example.com", key=key)
    assert isinstance(cipher, bytes)
    assert cipher.startswith(b"gAAAAA")


def test_encrypt_email_round_trip() -> None:
    """encrypt_email() → Fernet(key).decrypt() round-trips to the plaintext.

    Per AC-020.4.
    """
    key = Fernet.generate_key()
    plaintext = "jane@example.com"
    cipher = encrypt_email(plaintext, key=key)
    decrypted = Fernet(key).decrypt(cipher).decode("utf-8")
    assert decrypted == plaintext


def test_encrypt_email_round_trip_unicode() -> None:
    """encrypt_email() round-trips Unicode plaintext."""
    key = Fernet.generate_key()
    plaintext = "ñoño@example.com"
    cipher = encrypt_email(plaintext, key=key)
    decrypted = Fernet(key).decrypt(cipher).decode("utf-8")
    assert decrypted == plaintext


def test_encrypt_email_does_not_return_plaintext() -> None:
    """encrypt_email() MUST NOT return the plaintext (per AC-020.3)."""
    key = Fernet.generate_key()
    plaintext = "jane@example.com"
    cipher = encrypt_email(plaintext, key=key)
    assert cipher != plaintext.encode("utf-8")
    assert plaintext.encode("utf-8") not in cipher


def test_encrypt_email_different_each_call() -> None:
    """Fernet uses a per-message IV — encrypt_email() returns different ciphertexts.

    (The plaintext is the same but the IV/timestamp varies.)
    """
    key = Fernet.generate_key()
    c1 = encrypt_email("jane@example.com", key=key)
    c2 = encrypt_email("jane@example.com", key=key)
    assert c1 != c2


def test_encrypt_email_wrong_key_fails_decryption() -> None:
    """encrypt_email() with key A is NOT decryptable with key B.

    Per AC-020.6 (idempotency) / defense in depth — wrong key raises InvalidToken.
    """
    key_a = Fernet.generate_key()
    key_b = Fernet.generate_key()
    cipher = encrypt_email("jane@example.com", key=key_a)
    with pytest.raises(InvalidToken):
        Fernet(key_b).decrypt(cipher)


def test_encrypt_email_tampering_fails() -> None:
    """Tampering with a ciphertext makes Fernet.decrypt() raise InvalidToken."""
    key = Fernet.generate_key()
    cipher = encrypt_email("jane@example.com", key=key)
    # Flip one bit in the middle of the token
    tampered = bytearray(cipher)
    tampered[len(tampered) // 2] ^= 0xFF
    with pytest.raises(InvalidToken):
        Fernet(key).decrypt(bytes(tampered))


def test_encrypt_email_missing_key_raises() -> None:
    """encrypt_email() with key=None raises EncryptionKeyMissingError.

    Per AC-020.5.
    """
    with pytest.raises(EncryptionKeyMissingError):
        encrypt_email("jane@example.com", key=None)


def test_encrypt_email_invalid_key_raises() -> None:
    """encrypt_email() with a malformed key raises EncryptionKeyMissingError.

    Per A-020.e — 'not-a-valid-fernet-key' → caught and raised as
    EncryptionKeyMissingError so callers don't have to handle ValueError.
    """
    with pytest.raises(EncryptionKeyMissingError):
        encrypt_email("jane@example.com", key=b"not-a-valid-fernet-key")


def test_encrypt_email_empty_string_still_works() -> None:
    """encrypt_email('') succeeds (Fernet handles any bytes)."""
    key = Fernet.generate_key()
    cipher = encrypt_email("", key=key)
    assert cipher.startswith(b"gAAAAA")
    assert Fernet(key).decrypt(cipher).decode("utf-8") == ""


# ---- integration: hash + encrypt layered correctly ----


def test_hash_and_encrypt_layered() -> None:
    """hash_email() and encrypt_email() can coexist: one identifies, the other stores."""
    key = Fernet.generate_key()
    plaintext = "jane@example.com"
    h = hash_email(plaintext)  # 64-char pseudonym
    ct = encrypt_email(plaintext, key=key)  # ciphertext for storage

    # Hash identifies (deterministic), ciphertext stores (recoverable with key).
    assert hash_email(plaintext) == h
    assert Fernet(key).decrypt(ct).decode("utf-8") == plaintext
    # The two artifacts have different shapes and purposes.
    assert len(h) == 64
    assert ct.startswith(b"gAAAAA")
    assert h.encode("ascii") not in ct


def test_hash_email_output_is_str_not_bytes() -> None:
    """hash_email() returns a str (not bytes) for Pydantic / DB compatibility."""
    h = hash_email("jane@example.com")
    assert isinstance(h, str)


def test_encrypt_email_returns_bytes_not_str() -> None:
    """encrypt_email() returns bytes (per spec.md REQ-020 §2)."""
    key = Fernet.generate_key()
    cipher = encrypt_email("jane@example.com", key=key)
    assert isinstance(cipher, bytes)