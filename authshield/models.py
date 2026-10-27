"""
authshield.models — Pydantic Schemas for Request & Response Data
"""

from pydantic import BaseModel, Field


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: str = Field(..., description="Valid email address")
    password: str = Field(..., min_length=6, description="Plaintext password to be hashed")
    full_name: str | None = Field(default=None, description="Full name of user")
    role: str = Field(default="user", description="Role: 'user' or 'admin'")


class UserResponse(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    role: str
    scopes: list[str]
    disabled: bool = False
    created_at: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scopes: list[str]


class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []


class SecureMessage(BaseModel):
    status: str
    message: str
    authenticated_user: str
    granted_scopes: list[str]
    timestamp: str
