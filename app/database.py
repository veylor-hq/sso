"""Database connection and Beanie ODM initialization."""

import logging
from datetime import datetime, timezone
from typing import Optional
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from app.config import get_settings
from app.models.authorization_code import AuthorizationCode
from app.models.oauth_client import OAuthClient
from app.models.session import BrowserSession
from app.models.signing_key import SigningKey
from app.models.token_records import ActionToken
from app.models.user import User
from app.security.jwt import get_key_manager

logger = logging.getLogger("veylor.db")

_client: Optional[AsyncIOMotorClient] = None


async def init_db(client: Optional[AsyncIOMotorClient] = None, database_name: Optional[str] = None):
    """Initialize MongoDB connection and Beanie ODM."""
    global _client
    settings = get_settings()

    if client is not None:
        _client = client
        db_name = database_name or settings.MONGODB_DATABASE
    else:
        try:
            candidate_client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=1500)
            # Ping to verify MongoDB connectivity
            await candidate_client.admin.command("ping")
            _client = candidate_client
            db_name = settings.MONGODB_DATABASE
            logger.info("Connected to MongoDB at %s (%s)", settings.MONGODB_URL, db_name)
        except Exception as e:
            logger.warning(
                "MongoDB at %s is not reachable (%s). Falling back to standalone in-memory database for local evaluation.",
                settings.MONGODB_URL,
                str(e),
            )
            from mongomock_motor import AsyncMongoMockClient
            _client = AsyncMongoMockClient()
            db_name = "veylor_sso_standalone"

    db = _client[db_name]

    await init_beanie(
        database=db,
        document_models=[
            User,
            BrowserSession,
            OAuthClient,
            AuthorizationCode,
            SigningKey,
            ActionToken,
        ],
    )
    logger.info("Initialized Beanie ODM for database: %s", db_name)

    # Ensure signing key is loaded or generated
    km = get_key_manager()
    km.load_or_generate_keys()

    # Pre-seed initial first-party Veylor applications
    await seed_first_party_clients()


async def seed_first_party_clients():
    """Seed initial first-party trusted clients if they do not exist."""
    initial_clients = [
        {
            "client_id": "egarage",
            "client_name": "eGarage",
            "client_type": "public",
            "redirect_uris": [
                "https://egarageapp.uk/auth/callback",
                "http://localhost:3000/auth/callback",
            ],
            "allowed_scopes": ["openid", "profile", "email"],
            "trusted": True,
        },
        {
            "client_id": "relay",
            "client_name": "Veylor Relay",
            "client_type": "public",
            "redirect_uris": [
                "https://relay.veylor.dev/auth/callback",
                "http://localhost:3001/auth/callback",
            ],
            "allowed_scopes": ["openid", "profile", "email", "relay:send", "relay:read"],
            "trusted": True,
        },
        {
            "client_id": "pager",
            "client_name": "Veylor Pager",
            "client_type": "public",
            "redirect_uris": [
                "https://pager.veylor.dev/auth/callback",
                "http://localhost:3002/auth/callback",
            ],
            "allowed_scopes": ["openid", "profile", "email", "pager:read", "pager:write"],
            "trusted": True,
        },
        {
            "client_id": "warden",
            "client_name": "Veylor Warden",
            "client_type": "public",
            "redirect_uris": [
                "https://warden.veylor.dev/auth/callback",
                "http://localhost:3003/auth/callback",
            ],
            "allowed_scopes": ["openid", "profile", "email"],
            "trusted": True,
        },
    ]

    now = datetime.now(timezone.utc)
    for c in initial_clients:
        exists = await OAuthClient.find_one(OAuthClient.client_id == c["client_id"])
        if not exists:
            client = OAuthClient(
                client_id=c["client_id"],
                client_name=c["client_name"],
                client_type=c["client_type"],
                redirect_uris=c["redirect_uris"],
                allowed_scopes=c["allowed_scopes"],
                trusted=c["trusted"],
                disabled=False,
                created_at=now,
                updated_at=now,
            )
            await client.insert()
            logger.info("Seeded initial first-party OAuth client: %s", c["client_id"])


async def close_db():
    """Close MongoDB connection."""
    global _client
    if _client:
        _client.close()
        _client = None
