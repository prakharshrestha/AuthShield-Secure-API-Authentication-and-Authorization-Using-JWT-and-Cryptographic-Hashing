"""
authshield.database — In-Memory & Parameterized Secure User Store
"""

from datetime import datetime, timezone
from typing import Any
from authshield.security import hash_password


class UserDatabase:
    """In-memory thread-safe user database preloaded with hashed demo users."""

    def __init__(self):
        self._users: dict[str, dict[str, Any]] = {}
        self._seed_default_users()

    def _seed_default_users(self):
        # Admin User with full scopes
        self.create_user(
            username="admin",
            email="admin@authshield.io",
            password="AdminPassword123!",
            full_name="System Administrator",
            role="admin",
            scopes=["admin", "read", "write"]
        )
        # Standard User with read/write scopes
        self.create_user(
            username="alice",
            email="alice@authshield.io",
            password="AliceSecurePass456!",
            full_name="Alice Member",
            role="user",
            scopes=["read"]
        )

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        role: str = "user",
        scopes: list[str] | None = None
    ) -> dict[str, Any]:
        username_key = username.strip().lower()
        if username_key in self._users:
            raise ValueError(f"User '{username}' already exists.")

        now = datetime.now(timezone.utc).isoformat()
        assigned_scopes = scopes or (["admin", "read", "write"] if role == "admin" else ["read"])

        user_record = {
            "username": username.strip(),
            "email": email.strip().lower(),
            "hashed_password": hash_password(password),
            "full_name": full_name or username,
            "role": role,
            "scopes": assigned_scopes,
            "disabled": False,
            "created_at": now,
        }
        self._users[username_key] = user_record
        return user_record

    def get_user(self, username: str) -> dict[str, Any] | None:
        return self._users.get(username.strip().lower())

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        email_key = email.strip().lower()
        for user in self._users.values():
            if user["email"] == email_key:
                return user
        return None

    def list_users(self) -> list[dict[str, Any]]:
        return list(self._users.values())


# Global Database Instance
db = UserDatabase()
