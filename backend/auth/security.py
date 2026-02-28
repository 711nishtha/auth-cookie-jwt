import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

# RS256: asymmetric signing. Resource API only needs the public key to verify —
# private key never leaves the Auth Server. Symmetric (HS256) would require sharing
# the secret with every service that validates tokens — bad trust boundary.
#
# In production: load from PEM files, rotate with key versioning (kid header).
# For this demo we generate ephemeral keys at startup — tokens die with the process.
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    _private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIVATE_KEY = _private_key_obj.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    PUBLIC_KEY = _private_key_obj.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    ALGORITHM = "RS256"
except ImportError:
    # Fallback for environments without cryptography — HS256 with random secret
    # NOT for production; asymmetric signing is strongly preferred
    PRIVATE_KEY = PUBLIC_KEY = secrets.token_hex(64)
    ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 15   # Short window limits blast radius of a leaked token
REFRESH_TOKEN_EXPIRE_DAYS = 7


def create_access_token(user_id: int, email: str, scopes: list[str] | None = None) -> str:
    """
    Mint a signed JWT. Claims follow RFC 7519.
    `sub` is the user_id (stable, not email — emails can change).
    `aud` scoping ensures this token is rejected by other services.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "scope": " ".join(scopes or ["read:profile"]),
        "iss": "auth-server",
        "aud": "resource-api",
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        # jti would enable per-token revocation via blocklist — omitted for demo
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Validate signature, expiry, issuer, and audience in one call.
    Raises JWTError on any failure — callers convert to 401.
    Never catch broadly; let invalid tokens fail loudly.
    """
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=[ALGORITHM],
        audience="resource-api",
        issuer="auth-server",
    )


def create_refresh_token() -> tuple[str, str]:
    """
    Return (raw_token, token_hash).
    Raw token is sent to the client once and never stored.
    Hash is persisted in DB — preimage resistance means a DB leak alone is not enough.
    """
    raw = secrets.token_urlsafe(32)   # 256 bits of entropy
    hashed = _hash_token(raw)
    return raw, hashed


def _hash_token(raw: str) -> str:
    """SHA-256 hex digest. Fast is acceptable here — this is not a password."""
    return hashlib.sha256(raw.encode()).hexdigest()


def hash_refresh_token(raw: str) -> str:
    return _hash_token(raw)


def refresh_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
