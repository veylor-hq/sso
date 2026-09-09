"""Veylor User document model."""

from datetime import datetime, timezone
from typing import Optional
from beanie import Document, Indexed
from pydantic import Field
import pymongo


class User(Document):
    # Immutable opaque Veylor ID (e.g., usr_01J...)
    # This MUST be the OIDC `sub` claim. Never use email as `sub`.
    id: str = Field(..., description="Immutable opaque ID: usr_01J...")
    email: Indexed(str, unique=True) = Field(..., description="Normalized, lowercase email")
    email_verified: bool = Field(default=False)
    password_hash: str = Field(..., description="Argon2id password hash")
    name: str = Field(..., min_length=1, max_length=100)
    given_name: Optional[str] = Field(default=None, max_length=50)
    family_name: Optional[str] = Field(default=None, max_length=50)
    avatar_url: Optional[str] = Field(default=None)
    google_sub: Optional[str] = Field(default=None)
    auth_provider: str = Field(default="local")
    disabled: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login_at: Optional[datetime] = Field(default=None)

    class Settings:
        name = "users"
        indexes = [
            [("email", pymongo.ASCENDING)],
            [("created_at", pymongo.DESCENDING)],
        ]
