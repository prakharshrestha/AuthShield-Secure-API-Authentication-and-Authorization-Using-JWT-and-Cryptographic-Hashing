"""
authshield.app — FastAPI Application & Route Controllers
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import (
    OAuth2PasswordRequestForm,
    SecurityScopes,
)

from authshield.models import (
    UserRegister,
    UserResponse,
    Token,
    TokenData,
    SecureMessage,
)
from authshield.database import db
from authshield.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    oauth2_scheme,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    USE_ARGON2,
)

app = FastAPI(
    title="AuthShield API",
    description=(
        "**AuthShield**: Secure API Authentication and Authorization System\n\n"
        "Features:\n"
        "- **Cryptographic Password Hashing**: Argon2id / PBKDF2-HMAC-SHA256\n"
        "- **JSON Web Tokens (JWT)**: RFC 7519 HMAC-SHA256 authenticated bearer tokens\n"
        "- **Role-Based Access Control (RBAC)**: Fine-grained OAuth2 scopes (`read`, `write`, `admin`)\n"
        "- **Timing-Attack Resistance**: Constant-time signature & password verification\n"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Dependency: Authenticate and Authorize User from JWT ─────────────────────

async def get_current_user(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)]
) -> dict:
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or signature expired.",
        headers={"WWW-Authenticate": authenticate_value},
    )

    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication error: {str(err)}",
            headers={"WWW-Authenticate": authenticate_value},
        )

    user = db.get_user(username)
    if user is None:
        raise credentials_exception
    if user.get("disabled"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user account.")

    # Validate that token contains required security scopes
    for required_scope in security_scopes.scopes:
        if required_scope not in token_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: requires '{required_scope}' scope.",
                headers={"WWW-Authenticate": authenticate_value},
            )

    return user


# ── Authentication Endpoints ─────────────────────────────────────────────────

@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="Register a new user account"
)
async def register(user_data: UserRegister):
    """
    Register a new user. The password is cryptographically hashed using
    Argon2id (or PBKDF2) before persisting. Raw plaintext is never stored.
    """
    try:
        user_record = db.create_user(
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            role=user_data.role,
        )
        return UserResponse(
            username=user_record["username"],
            email=user_record["email"],
            full_name=user_record["full_name"],
            role=user_record["role"],
            scopes=user_record["scopes"],
            disabled=user_record["disabled"],
            created_at=user_record["created_at"],
        )
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))


@app.post(
    "/auth/token",
    response_model=Token,
    tags=["Authentication"],
    summary="Obtain JWT access token (OAuth2 Password Flow)"
)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    Authenticate using username and password. On successful verification,
    returns an RFC 7519 JSON Web Token (JWT) with assigned scopes.
    """
    user = db.get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Scopes granted: intersection of user's scopes and requested scopes (or all if none requested)
    user_scopes = user.get("scopes", ["read"])
    if form_data.scopes:
        granted_scopes = [s for s in form_data.scopes if s in user_scopes]
    else:
        granted_scopes = user_scopes

    token_data = {
        "sub": user["username"],
        "email": user["email"],
        "role": user["role"],
        "scopes": granted_scopes,
    }
    access_token = create_access_token(token_data)

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        scopes=granted_scopes,
    )


@app.get(
    "/auth/me",
    response_model=UserResponse,
    tags=["Authentication"],
    summary="Get current authenticated user profile"
)
async def read_users_me(
    current_user: Annotated[dict, Security(get_current_user, scopes=["read"])]
):
    """
    Protected route: Returns the profile of the caller validated from the JWT token.
    Requires at least 'read' scope.
    """
    return UserResponse(
        username=current_user["username"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        scopes=current_user["scopes"],
        disabled=current_user["disabled"],
        created_at=current_user["created_at"],
    )


# ── Protected Business Endpoints (Role & Scope Authorization) ────────────────

@app.get("/api/public", tags=["Public"], summary="Public Unauthenticated Endpoint")
async def public_endpoint():
    """Unprotected endpoint accessible by any external client."""
    return {
        "status": "success",
        "message": "AuthShield Public API — No authentication required.",
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


@app.get(
    "/api/user-data",
    response_model=SecureMessage,
    tags=["Protected"],
    summary="Access user data (Requires 'read' scope)"
)
async def read_user_data(
    current_user: Annotated[dict, Security(get_current_user, scopes=["read"])]
):
    """Protected resource accessible to users with the 'read' scope."""
    return SecureMessage(
        status="success",
        message="Confidential user data retrieved successfully.",
        authenticated_user=current_user["username"],
        granted_scopes=current_user["scopes"],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get(
    "/api/admin-secrets",
    response_model=SecureMessage,
    tags=["Protected"],
    summary="Access high-privilege administrative secrets (Requires 'admin' scope)"
)
async def read_admin_secrets(
    current_user: Annotated[dict, Security(get_current_user, scopes=["admin"])]
):
    """Highly protected resource strictly requiring 'admin' scope."""
    return SecureMessage(
        status="success",
        message="Master system secrets accessed under administrative authority.",
        authenticated_user=current_user["username"],
        granted_scopes=current_user["scopes"],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/health", tags=["System"], summary="Cryptographic and system status")
async def health_check():
    """Verify application integrity, active cryptographic hashing algorithm, and JWT parameters."""
    return {
        "status": "operational",
        "service": "AuthShield",
        "version": "1.0.0",
        "crypto": {
            "password_hashing": "Argon2id" if USE_ARGON2 else "PBKDF2-HMAC-SHA256",
            "jwt_algorithm": "HMAC-SHA256 (HS256)",
            "token_expiry_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
        },
        "registered_users_count": len(db.list_users()),
    }
