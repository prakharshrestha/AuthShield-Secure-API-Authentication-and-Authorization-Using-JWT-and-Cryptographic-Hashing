# AuthShield — Secure API Authentication & Authorization Using JWT & Cryptographic Hashing

> **CNS Project | Dept. of Computer Science & Engineering**
> Faculty Guide: Prof. Amey Muchandi

AuthShield is a production-grade API authentication and authorization system built with **FastAPI**, demonstrating real-world application of cryptographic techniques covered in the Cryptography & Network Security course.

---

## Team

| SRN | Name |
|---|---|
| 02FE23BCS082 | Sanjana Patil |
| 02FE23BCS086 | Vishal Balu Waghamare |
| 02FE23BCS089 | Karthik Kamaldinni |
| 02FE23BCS090 | Prakhar Shrestha |

---

## Key Features

- **Argon2id Password Hashing** — PHC winner; memory-hard (64 MB/attempt), GPU/ASIC-resistant; PBKDF2-HMAC-SHA256 (200k rounds) as fallback
- **JWT (RFC 7519) with HMAC-SHA256** — Pure-Python token issuance & verification with `hmac.compare_digest` for constant-time, timing-attack-resistant signature checks
- **OAuth2 Scope-Based Authorization** — Three-tier roles (`read`, `write`, `admin`) enforced per-route via FastAPI `SecurityScopes`
- **Auto-generated API Docs** — Swagger UI at `/docs` and ReDoc at `/redoc` with JWT Bearer Auth integrated
- **14 Automated Tests** — Full pytest coverage: crypto primitives, JWT tamper/expiry, login flow, scope enforcement, admin access

---

## Project Structure

```
authshield/
├── app.py          # FastAPI routes: /auth/register, /auth/token, /auth/me, /api/*, /health
├── security.py     # Argon2id/PBKDF2 hashing, HMAC-SHA256 JWT creation & verification
├── database.py     # In-memory user store with seeded admin/alice users
├── models.py       # Pydantic v2 schemas: UserRegister, Token, UserResponse, SecureMessage
main.py             # Uvicorn ASGI entry point
tests/
└── test_authshield.py  # 14 tests (pytest + FastAPI TestClient)
```

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | None | Register new user (password hashed with Argon2id) |
| POST | `/auth/token` | None | OAuth2 login — returns HMAC-SHA256 signed JWT |
| GET | `/auth/me` | Bearer (`read`) | Returns authenticated user profile |
| GET | `/api/public` | None | Public endpoint |
| GET | `/api/user-data` | Bearer (`read`) | Protected user data |
| GET | `/api/admin-secrets` | Bearer (`admin`) | Admin-only protected resource |
| GET | `/health` | None | Crypto stack status |

---

## Setup & Run

```bash
# Install dependencies
pip install fastapi uvicorn argon2-cffi pydantic

# Run the server
python main.py
# → API available at http://127.0.0.1:8000
# → Docs at http://127.0.0.1:8000/docs

# Run tests
pytest tests/test_authshield.py -v
```

---

## Cryptographic Design

### Password Hashing
```
Argon2id(password, salt, time_cost=3, memory_cost=64MB, parallelism=4)
Fallback: PBKDF2-HMAC-SHA256(password, salt, iterations=200_000)
```

### JWT Token Structure (RFC 7519)
```
Base64URL({"alg":"HS256","typ":"JWT"})
  . Base64URL({"sub":"user","iat":..,"exp":..,"role":"user","scopes":["read"]})
  . HMAC-SHA256(secret, header.payload)   ← verified with hmac.compare_digest
```

### Threat Model Coverage
| Threat | Defense |
|---|---|
| Credential brute-force | Argon2id — 64 MB RAM per attempt |
| JWT forgery/tampering | HMAC-SHA256 + constant-time verify |
| Privilege escalation | OAuth2 scopes enforced per route |
| Replay attacks | JWT `exp` claim validated on every request |
| Timing side-channels | `hmac.compare_digest` throughout |

---

## Test Results

```
tests/test_authshield.py::test_password_hashing_and_verification  PASSED
tests/test_authshield.py::test_empty_password_rejection           PASSED
tests/test_authshield.py::test_jwt_token_roundtrip                PASSED
tests/test_authshield.py::test_jwt_tampered_signature_rejection   PASSED
tests/test_authshield.py::test_jwt_expired_token_rejection        PASSED
tests/test_authshield.py::test_public_endpoint                    PASSED
tests/test_authshield.py::test_health_check_endpoint              PASSED
tests/test_authshield.py::test_user_registration_flow             PASSED
tests/test_authshield.py::test_duplicate_registration_fails       PASSED
tests/test_authshield.py::test_login_oauth2_success               PASSED
tests/test_authshield.py::test_login_invalid_credentials_fails    PASSED
tests/test_authshield.py::test_access_protected_me_endpoint       PASSED
tests/test_authshield.py::test_scope_authorization_enforcement    PASSED
tests/test_authshield.py::test_admin_access_success               PASSED

14 passed in 5.10s
```
