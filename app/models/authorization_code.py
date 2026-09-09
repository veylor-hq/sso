"""Authorization code model."""

from datetime import datetime, timezone
from typing import List, Optional
from beanie import Document, Indexed
from pydantic import Field
import pymongo


class AuthorizationCode(Document):
    # Cryptographically random code hashed with SHA-256
    code_hash: Indexed(str, unique=True) = Field(..., description="SHA-256 hash of plaintext authorization code")
    user_id: Indexed(str) = Field(..., description="References User.id")
    client_id: Indexed(str) = Field(..., description="References OAuthClient.client_id")
    redirect_uri: str = Field(..., description="Redirect URI bound at /authorize")
    scopes: List[str] = Field(default_factory=list)
    code_challenge: str = Field(..., description="PKCE code challenge string")
    code_challenge_method: str = Field(default="S256", description="Must be strictly S256")
    nonce: Optional[str] = Field(default=None, description="Preserved OIDC nonce value")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Indexed(datetime) = Field(..., description="Short-lived expiration timestamp (typically 60s)")
    used_at: Optional[datetime] = Field(default=None, description="Marked immediately upon exchange to prevent replay")

    @property
    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        exp = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return self.used_at is None and exp > now

    class Settings:
        name = "authorization_codes"
        indexes = [
            [("code_hash", pymongo.ASCENDING)],
            [("expires_at", pymongo.ASCENDING)],
        ]
