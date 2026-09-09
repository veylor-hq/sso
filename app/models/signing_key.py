"""SigningKey model for storing asymmetric public keys."""

from datetime import datetime, timezone
from beanie import Document, Indexed
from pydantic import Field
import pymongo


class SigningKey(Document):
    kid: Indexed(str, unique=True) = Field(..., description="Key ID (e.g. veylor-sso-key-1)")
    algorithm: str = Field(default="RS256", description="Signature algorithm")
    public_key_pem: str = Field(..., description="Public key in PEM format")
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "signing_keys"
        indexes = [
            [("kid", pymongo.ASCENDING)],
        ]
