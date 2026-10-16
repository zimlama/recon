"""Tests for the JwtKeyManager — RS256 sign/verify + kid rotation (PR-J1).

Spec invariants covered (engram #1371):

- §2 Scenario "Access token payload shape": RS256 with kid header.
- §4 INV-1:  AccessToken verify fails with token_expired between
  T+900s and T+905s (5s clock-skew budget).
- §4 INV-11: key rotation via kid; verifier accepts both old + new for
  one access-TTL window after rotation.

We use ephemeral RSA keys generated in-memory for every test. We DO NOT
read from disk because the file paths + file modes are operator concerns
(shipped in PR-J7 ops docs). The PEM-loading path is exercised by a
separate helper test that writes a temp keypair.

Security regression tests:

- ``alg: none`` is rejected (PyJWT 2.x forbids by default but we double
  the lock at the service layer).
- ``alg: HS256`` with the public key as HMAC secret is rejected.
- Tampered signature is rejected.
- Wrong kid is rejected.
- Tokens with ``nbf`` in the future are rejected (with leeway).
- Tokens with ``aud`` mismatch are rejected.
- Tokens with ``iss`` mismatch are rejected.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.jwt import (
    InvalidTokenError,
    JwtKeyManager,
    KeyPairMismatchError,
    KeySourceMissingError,
)

# ---------------------------------------------------------------------------
# Ephemeral RSA keypair fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rsa_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh 2048-bit RSA keypair as (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture
def keypair_paths(tmp_path: Path, rsa_keypair: tuple[bytes, bytes]) -> Iterator[tuple[Path, Path]]:
    """Write the keypair to disk and yield (private_path, public_path)."""
    priv, pub = rsa_keypair
    p = tmp_path / "priv.pem"
    pu = tmp_path / "pub.pem"
    p.write_bytes(priv)
    pu.write_bytes(pub)
    return p, pu


# ---------------------------------------------------------------------------
# Spec §2 — access token shape
# ---------------------------------------------------------------------------


def test_sign_access_token_claims_match_spec(keypair_paths) -> None:
    """A freshly-signed token has the spec'd claim set + kid header."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        issuer="recon-auth",
    )

    claims = {
        "sub": "11111111-1111-1111-1111-111111111111",
        "role": "operator",
        "scopes": ["jobs:read"],
        "jti": "22222222-2222-2222-2222-222222222222",
    }
    token = mgr.sign(claims, ttl_seconds=900)
    assert isinstance(token, str)
    assert token.count(".") == 2  # JWT structure

    # Decode header without verification to inspect alg + kid.
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    assert header["kid"] == "k1"

    # Verify signature + standard claims.
    decoded = mgr.verify(token, ttl_seconds=900)
    for k, v in claims.items():
        assert (
            decoded[k] == v
        ), f"claim {k!r} round-trip mismatch: expected {v!r}, got {decoded.get(k)!r}"
    assert decoded["iss"] == "recon-auth"


def test_sign_includes_exp_and_iat_unless_keys(
    keypair_paths,
) -> None:
    """``exp`` is auto-added if missing; ``iat`` is auto-added."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=60)
    decoded = mgr.verify(token, ttl_seconds=60)
    assert "exp" in decoded
    assert "iat" in decoded
    assert decoded["exp"] - decoded["iat"] == 60


# ---------------------------------------------------------------------------
# Spec §4 INV-1 — TTL budget (expiry + 5s leeway)
# ---------------------------------------------------------------------------


def test_expired_token_rejected(keypair_paths) -> None:
    """A token whose ``exp`` has passed is rejected."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    # Sign with ttl_seconds=-100 so the token is well past the default
    # 5s clock-skew budget. (A -1s token would be accepted because
    # PyJWT's leeway absorbs it — that's the next test.)
    token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=-100)
    with pytest.raises(InvalidTokenError) as ei:
        mgr.verify(token, ttl_seconds=900)
    assert "expired" in ei.value.reason


def test_expired_token_within_clock_skew_accepted(
    keypair_paths,
) -> None:
    """A token whose ``exp`` is at most ``leeway`` seconds in the past is accepted.

    PyJWT's ``leeway`` parameter absorbs minor clock skew across hosts.
    """
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        clock_skew_seconds=5,
    )
    # Sign with ttl_seconds=-3 (expired 3s ago) — within the 5s leeway.
    token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=-3)
    decoded = mgr.verify(token, ttl_seconds=900)
    assert decoded["sub"] == "user-1"


def test_expired_token_beyond_clock_skew_rejected(
    keypair_paths,
) -> None:
    """A token whose ``exp`` exceeds the leeway window is rejected."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        clock_skew_seconds=5,
    )
    token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=-10)
    with pytest.raises(InvalidTokenError):
        mgr.verify(token, ttl_seconds=900)


# ---------------------------------------------------------------------------
# Spec §4 INV-11 — kid dispatch + key rotation
# ---------------------------------------------------------------------------


def test_verify_with_correct_kid_dispatches(
    keypair_paths,
) -> None:
    """A token with kid=k1 is verified by the key whose kid matches."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=60)
    decoded = mgr.verify(token, ttl_seconds=900)
    assert decoded["sub"] == "user-1"


def test_unknown_kid_rejected(keypair_paths, tmp_path) -> None:
    """A token with kid=ghost is rejected (no verifier knows that kid)."""
    priv_path, pub_path = keypair_paths

    # Mint a token with kid="ghost" using a separate key (so the token is
    # well-formed but the manager doesn't know about that kid).
    ghost_priv_pem, ghost_pub_pem = _fresh_keypair_pems()
    ghost_priv_path = tmp_path / "ghost_priv.pem"
    ghost_pub_path = tmp_path / "ghost_pub.pem"
    ghost_priv_path.write_bytes(ghost_priv_pem)
    ghost_pub_path.write_bytes(ghost_pub_pem)
    ghost_mgr = JwtKeyManager(private_path=ghost_priv_path, public_path=ghost_pub_path, kid="ghost")
    token = ghost_mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=60)

    # Real manager does NOT know kid="ghost" → must reject.
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    with pytest.raises(InvalidTokenError) as ei:
        mgr.verify(token, ttl_seconds=900)
    assert "kid" in ei.value.reason or "unknown" in ei.value.reason.lower()


def test_key_rotation_grace_period_accepts_old_kid(keypair_paths, tmp_path) -> None:
    """After rotate(), tokens minted with the OLD kid still verify.

    The grace window equals the access TTL — anything minted within the
    last ``ACCESS_TTL_SECONDS`` seconds before rotation must keep working.
    """
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        access_ttl_seconds=900,
    )
    old_token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=60)

    # Mint a new keypair; load it as the primary key; k1 must stay active.
    new_priv, new_pub = _fresh_keypair_pems()
    new_priv_path = tmp_path / "new_priv.pem"
    new_pub_path = tmp_path / "new_pub.pem"
    new_priv_path.write_bytes(new_priv)
    new_pub_path.write_bytes(new_pub)

    mgr.rotate(new_private_path=new_priv_path, new_public_path=new_pub_path, new_kid="k2")
    decoded = mgr.verify(old_token, ttl_seconds=900)
    assert decoded["sub"] == "user-1"


def test_key_rotation_new_kid_works(keypair_paths, tmp_path) -> None:
    """After rotate(), freshly-minted tokens use the new kid and verify."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        access_ttl_seconds=900,
    )

    new_priv, new_pub = _fresh_keypair_pems()
    new_priv_path = tmp_path / "new_priv.pem"
    new_pub_path = tmp_path / "new_pub.pem"
    new_priv_path.write_bytes(new_priv)
    new_pub_path.write_bytes(new_pub)
    mgr.rotate(
        new_private_path=new_priv_path,
        new_public_path=new_pub_path,
        new_kid="k2",
    )

    new_token = mgr.sign({"sub": "user-2", "role": "admin", "scopes": []}, ttl_seconds=60)
    decoded = mgr.verify(new_token, ttl_seconds=900)
    assert decoded["sub"] == "user-2"
    header = pyjwt.get_unverified_header(new_token)
    assert header["kid"] == "k2"


# ---------------------------------------------------------------------------
# Security regression tests
# ---------------------------------------------------------------------------


def test_wrong_signature_rejected(keypair_paths, tmp_path) -> None:
    """A token signed with a different private key is rejected."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")

    # Build a SEPARATE manager around a DIFFERENT keypair (sign with priv_a,
    # verify with priv_c/pub_c). The token is well-formed under its own keypair
    # but does NOT match mgr's public key.
    other_priv, other_pub = _fresh_keypair_pems()
    other_priv_path = tmp_path / "other_priv.pem"
    other_pub_path = tmp_path / "other_pub.pem"
    other_priv_path.write_bytes(other_priv)
    other_pub_path.write_bytes(other_pub)
    other_mgr = JwtKeyManager(private_path=other_priv_path, public_path=other_pub_path, kid="k1")
    bad_token = other_mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=60)

    with pytest.raises(InvalidTokenError) as ei:
        mgr.verify(bad_token, ttl_seconds=900)
    assert ei.value.reason in ("bad_signature", "decode_failure")


def test_alg_none_attack_rejected(keypair_paths) -> None:
    """A token with ``alg: none`` (CVE-2015-9235 style) is rejected."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")

    # Hand-craft an alg=none token (no signature segment).
    import base64
    import json

    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT", "kid": "k1"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"sub": "u", "role": "admin", "scopes": [], "iss": "recon-auth"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    malicious = f"{header}.{payload}."

    with pytest.raises(InvalidTokenError):
        mgr.verify(malicious, ttl_seconds=900)


def test_alg_confusion_rs256_to_hs256_rejected(
    keypair_paths,
) -> None:
    """An attacker cannot downgrade RS256 → HS256 with the public key as the HMAC secret.

    PyJWT 2.x prevents encoding an HS256 token with a PEM asymmetric key
    (it raises ``InvalidKeyError`` at encode time). To exercise our
    *verify*-side defense we hand-craft an HS256 token using the public
    key bytes as the HMAC secret (the classic alg-confusion attack).
    The verifier MUST reject because the kid matches but the algorithm
    in the header is HS256, not RS256 — we pin ``algorithms=['RS256']``.
    """
    import base64
    import hashlib
    import hmac
    import json

    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")

    # Hand-craft the alg-confusion token.
    public_pem = pub_path.read_bytes()
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "u",
                    "role": "admin",
                    "scopes": [],
                    "iss": "recon-auth",
                    "aud": "recon-api",
                    "exp": int(time.time()) + 60,
                    "iat": int(time.time()),
                    "jti": "j1",
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    malicious = f"{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

    with pytest.raises(InvalidTokenError):
        mgr.verify(malicious, ttl_seconds=900)


def test_issuer_mismatch_rejected(keypair_paths) -> None:
    """A token with a foreign ``iss`` is rejected."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        issuer="recon-auth",
    )
    bad_token = pyjwt.encode(
        {
            "sub": "u",
            "role": "operator",
            "scopes": [],
            "iss": "evil-corp",
            "aud": "recon-api",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "jti": "j1",
        },
        key=priv_path.read_bytes(),
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(InvalidTokenError) as ei:
        mgr.verify(bad_token, ttl_seconds=900)
    assert ei.value.reason in ("iss_mismatch", "decode_failure")


def test_malformed_token_rejected(keypair_paths) -> None:
    """A non-JWT-shaped string is rejected without raising a stack trace."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    with pytest.raises(InvalidTokenError):
        mgr.verify("not-a-jwt", ttl_seconds=900)
    with pytest.raises(InvalidTokenError):
        mgr.verify("a.b", ttl_seconds=900)
    with pytest.raises(InvalidTokenError):
        mgr.verify("", ttl_seconds=900)


def test_nbf_in_future_rejected(keypair_paths) -> None:
    """A token whose ``nbf`` is in the future is rejected (with leeway)."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        clock_skew_seconds=5,
    )
    future_token = pyjwt.encode(
        {
            "sub": "u",
            "role": "operator",
            "scopes": [],
            "iss": "recon-auth",
            "iat": int(time.time()),
            "nbf": int(time.time()) + 600,  # 10 minutes in the future
            "exp": int(time.time()) + 1200,
            "jti": "j1",
        },
        key=priv_path.read_bytes(),
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(InvalidTokenError):
        mgr.verify(future_token, ttl_seconds=900)


# ---------------------------------------------------------------------------
# Construction + keypair consistency check
# ---------------------------------------------------------------------------


def test_constructor_loads_keys_from_disk(keypair_paths) -> None:
    """A manager constructed from on-disk PEMs signs + verifies a token."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=60)
    decoded = mgr.verify(token, ttl_seconds=900)
    assert decoded["sub"] == "user-1"


def test_constructor_raises_when_private_path_missing(keypair_paths, tmp_path) -> None:
    """Missing private key file → KeySourceMissingError."""
    _, pub_path = keypair_paths
    with pytest.raises(KeySourceMissingError):
        JwtKeyManager(
            private_path=tmp_path / "does-not-exist.pem",
            public_path=pub_path,
            kid="k1",
        )


def test_constructor_raises_when_keys_are_not_a_keypair(keypair_paths, tmp_path) -> None:
    """Mismatched private + public (from different keypairs) → KeyPairMismatchError.

    Catches operator mistakes like swapping env-var paths across hosts.
    """
    priv_path, _ = keypair_paths
    # Write a public key that DOES NOT match the private key.
    _other_priv, other_pub = _fresh_keypair_pems()
    other_pub_path = tmp_path / "wrong_pub.pem"
    other_pub_path.write_bytes(other_pub)
    # Touch the private so it exists.
    priv_path.write_bytes(priv_path.read_bytes())

    with pytest.raises(KeyPairMismatchError):
        JwtKeyManager(
            private_path=priv_path,
            public_path=other_pub_path,
            kid="k1",
        )


def test_invalid_token_error_carries_reason() -> None:
    """InvalidTokenError exposes ``reason`` and ``details`` for the router layer."""
    err = InvalidTokenError("test reason", details={"k": "v"})
    assert err.reason == "test reason"
    assert err.details == {"k": "v"}
    # Stringify does not leak the JWT itself.
    assert "test reason" in str(err)


def test_verify_rejects_token_with_undecodable_header(
    keypair_paths,
) -> None:
    """A token whose header segment isn't valid base64 JSON → malformed."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    # Header segment contains bytes that aren't valid b64url JSON.
    with pytest.raises(InvalidTokenError) as ei:
        mgr.verify("@@@.eyJzdWIiOiJ1In0.sig", ttl_seconds=900)
    assert ei.value.reason == "malformed"


def test_verify_rejects_token_without_kid_header(
    keypair_paths,
) -> None:
    """A well-formed token without a ``kid`` header is rejected."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    # Sign a normal token then strip the kid header — re-encode.
    token = mgr.sign({"sub": "user-1", "role": "operator", "scopes": []}, ttl_seconds=60)
    # Decode header, drop kid, re-encode.
    import base64
    import json

    h_b64, p_b64, s_b64 = token.split(".")

    def pad(s: str) -> str:
        return s + "=" * (-len(s) % 4)

    header = json.loads(base64.urlsafe_b64decode(pad(h_b64)))
    header.pop("kid", None)
    new_h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    no_kid_token = f"{new_h_b64}.{p_b64}.{s_b64}"

    with pytest.raises(InvalidTokenError) as ei:
        mgr.verify(no_kid_token, ttl_seconds=900)
    assert ei.value.reason == "malformed"


def test_audience_mismatch_rejected(keypair_paths) -> None:
    """A token whose ``aud`` doesn't match the manager's audience is rejected."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        audience="recon-api",
    )
    bad_token = pyjwt.encode(
        {
            "sub": "u",
            "role": "operator",
            "scopes": [],
            "iss": "recon-auth",
            "aud": "evil-api",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "jti": "j1",
        },
        key=priv_path.read_bytes(),
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(InvalidTokenError) as ei:
        mgr.verify(bad_token, ttl_seconds=900)
    assert ei.value.reason in ("aud_mismatch", "decode_failure")


def test_current_kid_property(keypair_paths) -> None:
    """``current_kid`` returns the active kid after ``rotate()``."""
    priv_path, pub_path = keypair_paths
    mgr = JwtKeyManager(private_path=priv_path, public_path=pub_path, kid="k1")
    assert mgr.current_kid == "k1"

    new_priv, new_pub = _fresh_keypair_pems()
    np_p = keypair_paths[0].parent / "np.pem"
    np_p.write_bytes(new_priv)
    npb = keypair_paths[0].parent / "npb.pem"
    npb.write_bytes(new_pub)

    mgr.rotate(new_private_path=np_p, new_public_path=npb, new_kid="k2")
    assert mgr.current_kid == "k2"


def test_constructor_raises_when_public_path_missing(keypair_paths, tmp_path) -> None:
    """Missing public key file → KeySourceMissingError."""
    priv_path, _ = keypair_paths
    with pytest.raises(KeySourceMissingError):
        JwtKeyManager(
            private_path=priv_path,
            public_path=tmp_path / "missing-pub.pem",
            kid="k1",
        )


def test_constructor_raises_when_private_key_not_rsa(keypair_paths, tmp_path) -> None:
    """Non-RSA private key (e.g. EC) at the configured path is rejected."""
    from cryptography.hazmat.primitives.asymmetric import ec

    _, pub_path = keypair_paths
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ec_path = tmp_path / "ec_priv.pem"
    ec_path.write_bytes(ec_pem)
    with pytest.raises(ValueError, match="not RSA"):
        JwtKeyManager(private_path=ec_path, public_path=pub_path, kid="k1")


def test_constructor_raises_when_public_key_not_rsa(keypair_paths, tmp_path) -> None:
    """Non-RSA public key (e.g. EC) at the configured path is rejected."""
    from cryptography.hazmat.primitives.asymmetric import ec

    priv_path, _ = keypair_paths
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ec_path = tmp_path / "ec_pub.pem"
    ec_path.write_bytes(ec_pub)
    with pytest.raises(ValueError, match="not RSA"):
        JwtKeyManager(private_path=priv_path, public_path=ec_path, kid="k1")


def test_module_does_not_export_unstable_helpers() -> None:
    """No leaked internal helpers — public surface is tight."""
    from app.auth import jwt as mod

    forbidden = {"_decode_token", "_check_kid", "_build_keyset"}
    leaked = [n for n in forbidden if hasattr(mod, n)]
    assert not leaked, f"internal helpers leaked: {leaked}"
    assert hasattr(mod, "JwtKeyManager")
    assert hasattr(mod, "InvalidTokenError")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_keypair_pems() -> tuple[bytes, bytes]:
    """Generate a fresh RSA keypair for adversarial tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem
