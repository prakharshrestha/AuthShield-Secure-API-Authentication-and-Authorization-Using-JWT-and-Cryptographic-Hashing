"""
authshield.security — Cryptographic Primitives & JWT Management

Implements:
1. Cryptographic Password Hashing: Argon2id (Winner of Password Hashing Competition)
   with fallback to NIST PBKDF2-HMAC-SHA256.
2. JSON Web Tokens (JWT - RFC 7519): Base64URL-encoded Header + Payload + HMAC-SHA256 signature.
3. OAuth2 Bearer Authentication & Scope-Based Authorization for FastAPI routes.
"""

import os
import hmac
import hashlib
import base64
import json
import time
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import (
    OAuth2PasswordBearer,
    SecurityScopes,
)

# ── Cryptographic Configuration ──────────────────────────────────────────────
SECRET_KEY = os.getenv(
    "AUTHSHIELD_SECRET_KEY",
    "f8d2b963e7c84511aa23c4a6b29f73e5124089aef3d91c6e49208a3951bc73d9"
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme definition
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/token",
    scopes={
        "read": "Read access to protected user resources.",
        "write": "Write/Modify permissions for application records.",
        "admin": "Administrative control and access to encrypted secrets.",
    },
)

# ── Password Hashing Engine ──────────────────────────────────────────────────
try:
    import argon2
    _hasher = argon2.PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16
    )
    USE_ARGON2 = True
except ImportError:
    USE_ARGON2 = False


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id (or PBKDF2-HMAC-SHA256 fallback).
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if USE_ARGON2:
        return _hasher.hash(password)
    else:
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, 32)
        return f"pbkdf2$sha256$200000${salt.hex()}${pwd_hash.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against its stored cryptographic hash.
    """
    if not plain_password or not hashed_password:
        return False
    if hashed_password.startswith("$argon2"):
        try:
            return _hasher.verify(hashed_password, plain_password)
        except Exception:
            return False
    elif hashed_password.startswith("pbkdf2$"):
        try:
            parts = hashed_password.split("$")
            _, algo, iterations, salt_hex, hash_hex = parts
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            computed = hashlib.pbkdf2_hmac(algo, plain_password.encode("utf-8"), salt, int(iterations), 32)
            return hmac.compare_digest(computed, expected)
        except Exception:
            return False
    return False


# ── Standards-Compliant JWT Implementation (RFC 7519 / RFC 7515) ─────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def create_access_token(
    data: dict[str, Any],
    expires_delta: int | None = None
) -> str:
    """
    Create a cryptographically signed JSON Web Token (JWT) using HMAC-SHA256.
    """
    to_encode = data.copy()
    now = int(time.time())
    expire = now + (expires_delta if expires_delta is not None else (ACCESS_TOKEN_EXPIRE_MINUTES * 60))

    to_encode.update({
        "iat": now,
        "exp": expire,
    })

    header = {"alg": ALGORITHM, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(to_encode, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Validate signature, timing, and decode the payload of a JWT.
    Raises ValueError on invalid token, signature tampering, or expiration.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT structure.")

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception:
        raise ValueError("Invalid Base64URL signature encoding.")

    # Constant-time comparison against timing attacks
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Cryptographic signature verification failed (tampered token).")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise ValueError("Invalid JSON in token payload.")

    # Expiration check
    exp = payload.get("exp")
    if exp is not None and time.time() > exp:
        raise ValueError("Token has expired.")

    return payload
