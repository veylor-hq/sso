"""Token records for email verification and password reset flows."""

from datetime import datetime, timezone
from typing import Optional
from beanie import Document, Indexed
from pydantic import Field
import pymongo


class ActionToken(Document):
    token_hash: Indexed(str, unique=True) = Field(..., description="SHA-256 hash of plaintext token")
    user_id: Indexed(str) = Field(..., description="Target User.id")
    token_type: str = Field(..., description="'password_reset' or 'email_verification'")
    expires_at: Indexed(datetime) = Field(...)
    used_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        exp = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return self.used_at is None and exp > now

    class Settings:
        name = "action_tokens"
        indexes = [
            [("token_hash", pymongo.ASCENDING)],
            [("user_id", pymongo.ASCENDING)],
            [("expires_at", pymongo.ASCENDING)],
        ]
