"""OAuth Client model for first-party and third-party registered applications."""

from datetime import datetime, timezone
from typing import List, Optional
from beanie import Document, Indexed
from pydantic import Field
import pymongo


class OAuthClient(Document):
    client_id: Indexed(str, unique=True) = Field(..., description="Unique client identifier (e.g. egarage)")
    client_name: str = Field(..., description="Display name of the application (e.g. eGarage)")
    client_type: str = Field(default="public", description="'public' (PKCE without secret) or 'confidential'")
    client_secret_hash: Optional[str] = Field(default=None, description="Hashed secret for confidential clients")
    redirect_uris: List[str] = Field(..., description="Exact whitelist of valid callback redirect URIs")
    allowed_scopes: List[str] = Field(
        default=["openid", "profile", "email"],
        description="Allowed scopes for this client",
    )
    allowed_origins: List[str] = Field(
        default_factory=list,
        description="Allowed web origins permitted to use SSO for this client",
    )
    # If trusted=True, skip interactive consent screen for standard scopes
    trusted: bool = Field(default=False, description="First-party trusted application")
    disabled: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "oauth_clients"
        indexes = [
            [("client_id", pymongo.ASCENDING)],
        ]
