"""
tests/test_authshield.py — Automated Test Suite for AuthShield API
"""

import os
import sys
# Ensure base directory is importable for authshield
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.append(base_dir)

import time
import pytest
from fastapi.testclient import TestClient

from authshield.app import app
from authshield.database import db
from authshield.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    SECRET_KEY,
)

client = TestClient(app)


# ── Cryptographic Hashing Tests ──────────────────────────────────────────────

def test_password_hashing_and_verification():
    raw_pass = "SuperSecurePassword123!"
    hashed = hash_password(raw_pass)

    assert hashed != raw_pass
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_empty_password_rejection():
    with pytest.raises(ValueError):
        hash_password("")


# ── JWT Primitives & Signature Tests ────────────────────────────────────────

def test_jwt_token_roundtrip():
    payload = {"sub": "testuser", "role": "user", "scopes": ["read"]}
    token = create_access_token(payload, expires_delta=300)

    decoded = decode_access_token(token)
    assert decoded["sub"] == "testuser"
    assert decoded["role"] == "user"
    assert "read" in decoded["scopes"]
    assert "exp" in decoded


def test_jwt_tampered_signature_rejection():
    payload = {"sub": "testuser", "role": "user"}
    token = create_access_token(payload, expires_delta=300)

    # Tamper with the token signature
    parts = token.split(".")
    tampered_sig = parts[2][:-4] + "AAAA"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with pytest.raises(ValueError, match="tampered token"):
        decode_access_token(tampered_token)


def test_jwt_expired_token_rejection():
    payload = {"sub": "expireduser"}
    # Token expired 10 seconds ago
    token = create_access_token(payload, expires_delta=-10)

    with pytest.raises(ValueError, match="expired"):
        decode_access_token(token)


# ── API Route & Authentication Integration Tests ─────────────────────────────

def test_public_endpoint():
    response = client.get("/api/public")
    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_health_check_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "crypto" in data


def test_user_registration_flow():
    reg_data = {
        "username": "bob_tester",
        "email": "bob@example.com",
        "password": "BobSecurePassword123!",
        "full_name": "Bob Tester",
        "role": "user"
    }
    response = client.post("/auth/register", json=reg_data)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "bob_tester"
    assert data["email"] == "bob@example.com"
    assert "password" not in data  # Never expose passwords


def test_duplicate_registration_fails():
    reg_data = {
        "username": "bob_tester",
        "email": "bob_duplicate@example.com",
        "password": "Password123!",
    }
    response = client.post("/auth/register", json=reg_data)
    assert response.status_code == 400


def test_login_oauth2_success():
    login_data = {
        "username": "alice",
        "password": "AliceSecurePass456!"
    }
    response = client.post("/auth/token", data=login_data)
    assert response.status_code == 200
    token_json = response.json()
    assert "access_token" in token_json
    assert token_json["token_type"] == "bearer"
    assert "read" in token_json["scopes"]


def test_login_invalid_credentials_fails():
    login_data = {
        "username": "alice",
        "password": "IncorrectPassword!"
    }
    response = client.post("/auth/token", data=login_data)
    assert response.status_code == 401


def test_access_protected_me_endpoint():
    # Login as alice
    login_res = client.post("/auth/token", data={"username": "alice", "password": "AliceSecurePass456!"})
    token = login_res.json()["access_token"]

    # Access /auth/me with Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "alice"


def test_scope_authorization_enforcement():
    # Login as alice (who only has 'read' scope, NOT 'admin')
    login_res = client.post("/auth/token", data={"username": "alice", "password": "AliceSecurePass456!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Accessing read endpoint succeeds
    read_res = client.get("/api/user-data", headers=headers)
    assert read_res.status_code == 200

    # Accessing admin endpoint MUST fail with 403 Forbidden
    admin_res = client.get("/api/admin-secrets", headers=headers)
    assert admin_res.status_code == 403
    assert "Insufficient permissions" in admin_res.json()["detail"]


def test_admin_access_success():
    # Login as admin
    login_res = client.post("/auth/token", data={"username": "admin", "password": "AdminPassword123!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Accessing admin endpoint succeeds
    admin_res = client.get("/api/admin-secrets", headers=headers)
    assert admin_res.status_code == 200
    assert admin_res.json()["status"] == "success"
