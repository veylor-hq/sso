"""BrowserSession model for server-side SSO sessions."""

from datetime import datetime, timezone
from typing import Optional
from beanie import Document, Indexed
from pydantic import Field
import pymongo


class BrowserSession(Document):
    id: str = Field(..., description="Unique session record ID (ULID or UUID)")
    # SHA-256 hash of the cryptographically random session token cookie
    session_hash: Indexed(str, unique=True) = Field(..., description="SHA-256 hash of plaintext cookie token")
    user_id: Indexed(str) = Field(..., description="References User.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Indexed(datetime) = Field(..., description="Session expiration timestamp")
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revoked_at: Optional[datetime] = Field(default=None)
    ip_address: Optional[str] = Field(default=None)
    user_agent: Optional[str] = Field(default=None)

    @property
    def is_active(self) -> bool:
        now = datetime.now(timezone.utc)
        exp = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return self.revoked_at is None and exp > now

    class Settings:
        name = "sessions"
        indexes = [
            [("session_hash", pymongo.ASCENDING)],
            [("user_id", pymongo.ASCENDING)],
            [("expires_at", pymongo.ASCENDING)],
        ]
