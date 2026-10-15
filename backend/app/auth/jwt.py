"""JwtKeyManager — RS256 sign/verify + kid rotation (PR-J1, sec-auth-jwt).

Spec coverage (engram #1371):

- §2 Scenario "Access token payload shape": RS256 + ``kid`` header.
- §4 INV-1: TTL budget enforced via PyJWT ``leeway`` (default 5 s).
- §4 INV-11: key rotation grace window — after ``rotate()`` both old and
  new ``kid``s verify for one ``ACCESS_TTL_SECONDS`` window.

Threat model recap:

- Algorithm confusion: we pin ``algorithms=['RS256']`` at verify time so
  an attacker cannot downgrade to HS256 with the public key as the HMAC
  secret (CVE-2015-9235 / CVE-2016-10555 class).
- ``alg: none``: PyJWT 2.x refuses by default; we never whitelist ``none``.
- Kid header injection: the verifier only accepts kids in the active
  keyset. Unknown kids → InvalidTokenError.
- Keypair mismatch at boot: detected with a sign/verify smoke test so an
  operator who swapped ``JWT_PRIVATE_KEY_PATH`` and ``JWT_PUBLIC_KEY_PATH``
  across hosts fails-loud at startup instead of 401ing every request.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, cast

import jwt as pyjwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

# --- Public exception types -------------------------------------------------


class InvalidTokenError(Exception):
    """JWT failed verification. ``reason`` is a router-mappable tag.

    Examples: ``"expired"``, ``"bad_signature"``, ``"unknown_kid"``,
    ``"iss_mismatch"``, ``"malformed"``.
    """

    def __init__(self, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.details = details or {}


class KeySourceMissingError(FileNotFoundError):
    """The PEM file at the configured path does not exist."""


class KeyPairMismatchError(ValueError):
    """The private + public keys are not a matching keypair."""


# Typed constant so the router layer can map reasons to HTTP status codes
# without duplicating the magic-string catalog.
INVALID_TOKEN_DETAILS: dict[str, str] = {
    "expired": "token_expired",
    "bad_signature": "token_invalid",
    "unknown_kid": "token_invalid",
    "iss_mismatch": "token_invalid",
    "aud_mismatch": "token_invalid",
    "malformed": "token_invalid",
    "decode_failure": "token_invalid",
}


# --- The manager ------------------------------------------------------------


class JwtKeyManager:
    """Sign + verify JWTs with an RS256 keypair; rotate via ``rotate()``.

    Holds an in-memory keyset keyed by ``kid``. After construction, ``sign``
    always uses the CURRENT (primary) kid. ``verify`` accepts ANY kid in
    the keyset, so tokens minted in the grace window keep working.

    All methods are sync; the FastAPI dependency wraps them in
    ``asyncio.to_thread`` (PR-J3).
    """

    DEFAULT_ISSUER = "recon-auth"
    DEFAULT_AUDIENCE = "recon-api"
    DEFAULT_CLOCK_SKEW_SECONDS = 5
    DEFAULT_ACCESS_TTL_SECONDS = 900

    def __init__(
        self,
        *,
        private_path: Path | str,
        public_path: Path | str,
        kid: str,
        issuer: str = DEFAULT_ISSUER,
        audience: str = DEFAULT_AUDIENCE,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
        access_ttl_seconds: int = DEFAULT_ACCESS_TTL_SECONDS,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._clock_skew_seconds = clock_skew_seconds
        self._access_ttl_seconds = access_ttl_seconds

        priv = self._load_private_pem(Path(private_path))
        pub = self._load_public_pem(Path(public_path))
        self._verify_keypair_match(priv, pub)

        # Keyset: kid -> (signing key, verifying key). Single key at boot.
        self._keysets: dict[str, _KeyEntry] = {kid: _KeyEntry(private_key=priv, public_key=pub)}
        self._current_kid = kid

    # ---- Signing -----------------------------------------------------------

    def sign(self, claims: dict[str, Any], *, ttl_seconds: int) -> str:
        """Sign ``claims`` as an RS256 JWT with the current kid.

        ``exp`` and ``iat`` are auto-populated if not present. ``jti`` is
        NOT auto-populated — the caller (AuthService.login) sets it to a
        uuid4 so audit-log rows can correlate a token to its jti.
        """
        now = int(time.time())
        full_claims = dict(claims)
        full_claims.setdefault("iat", now)
        full_claims.setdefault("exp", now + ttl_seconds)
        full_claims.setdefault("iss", self._issuer)
        full_claims.setdefault("aud", self._audience)
        if "jti" not in full_claims:
            full_claims["jti"] = str(uuid.uuid4())

        entry = self._keysets[self._current_kid]
        return pyjwt.encode(
            full_claims,
            key=entry.private_key,
            algorithm="RS256",
            headers={"kid": self._current_kid, "typ": "JWT"},
        )

    # ---- Verifying ---------------------------------------------------------

    def verify(self, token: str, *, ttl_seconds: int | None = None) -> dict[str, Any]:
        """Verify signature + standard claims, return the claims.

        Raises ``InvalidTokenError`` with a router-mappable ``reason`` on
        any failure. We deliberately collapse all signature / format errors
        into the same exception family so the router cannot accidentally
        leak which check failed (no oracle).
        """
        if not isinstance(token, str) or not token or token.count(".") != 2:
            raise InvalidTokenError("malformed")

        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.exceptions.InvalidTokenError as e:
            raise InvalidTokenError("malformed", details={"err": str(e)}) from e

        kid = header.get("kid")
        if not isinstance(kid, str):
            raise InvalidTokenError("malformed", details={"err": "missing kid"})
        entry = self._keysets.get(kid)
        if entry is None:
            raise InvalidTokenError("unknown_kid", details={"kid": kid})

        try:
            decoded = pyjwt.decode(
                token,
                key=entry.public_key,
                algorithms=["RS256"],  # pins algorithm — defeats downgrade
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._clock_skew_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except pyjwt.ExpiredSignatureError as e:
            raise InvalidTokenError(
                "expired", details={"err": str(e), "ttl_seconds": ttl_seconds}
            ) from e
        except pyjwt.InvalidIssuerError as e:
            raise InvalidTokenError("iss_mismatch", details={"err": str(e)}) from e
        except pyjwt.InvalidAudienceError as e:
            raise InvalidTokenError("aud_mismatch", details={"err": str(e)}) from e
        except pyjwt.InvalidSignatureError as e:
            raise InvalidTokenError("bad_signature", details={"err": str(e)}) from e
        except pyjwt.InvalidTokenError as e:
            raise InvalidTokenError("decode_failure", details={"err": str(e)}) from e

        return cast(dict[str, Any], decoded)

    # ---- Rotation ----------------------------------------------------------

    def rotate(
        self,
        *,
        new_private_path: Path | str,
        new_public_path: Path | str,
        new_kid: str,
    ) -> None:
        """Add a new key to the keyset; the old key keeps verifying for
        one access-TTL window so in-flight tokens don't break.

        After the TTL elapses, operators can call ``drop_old_key(old_kid)``
        (PR-J3 ops utility — not part of this PR).
        """
        new_priv = self._load_private_pem(Path(new_private_path))
        new_pub = self._load_public_pem(Path(new_public_path))
        self._verify_keypair_match(new_priv, new_pub)

        self._keysets[new_kid] = _KeyEntry(private_key=new_priv, public_key=new_pub)
        self._current_kid = new_kid

    @property
    def current_kid(self) -> str:
        return self._current_kid

    # ---- PEM loading -------------------------------------------------------

    @staticmethod
    def _load_private_pem(path: Path) -> RSAPrivateKey:
        if not path.exists():
            raise KeySourceMissingError(f"private key not found: {path}")
        pem = path.read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"private key at {path} is not RSA")
        return key

    @staticmethod
    def _load_public_pem(path: Path) -> RSAPublicKey:
        if not path.exists():
            raise KeySourceMissingError(f"public key not found: {path}")
        pem = path.read_bytes()
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError(f"public key at {path} is not RSA")
        return key

    @staticmethod
    def _verify_keypair_match(priv: RSAPrivateKey, pub: RSAPublicKey) -> None:
        """Sign a throwaway payload with ``priv`` and verify with ``pub``."""
        msg = b"keypair-match-probe"
        sig = priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        try:
            pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            raise KeyPairMismatchError(
                "private + public keys do not form a matching keypair"
            ) from e


class _KeyEntry:
    """Internal: holds the private (signing) and public (verifying) keys for one kid."""

    __slots__ = ("private_key", "public_key")

    def __init__(self, private_key: RSAPrivateKey, public_key: RSAPublicKey) -> None:
        self.private_key = private_key
        self.public_key = public_key
