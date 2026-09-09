"""Server-side browser session management for Single Sign-On."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from app.config import get_settings
from app.models.session import BrowserSession
from app.security.random import generate_opaque_id, generate_opaque_token, hash_token


async def create_session(
    user_id: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[BrowserSession, str]:
    """Create a new server-side session.

    Returns the BrowserSession document and the raw plaintext session token to set in the cookie.
    Only the SHA-256 hash of the token is stored in the database.
    """
    settings = get_settings()
    raw_token = generate_opaque_token(32)
    token_hash = hash_token(raw_token)
    session_id = generate_opaque_id(prefix="ses")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.SESSION_TTL_SECONDS)

    session = BrowserSession(
        id=session_id,
        session_hash=token_hash,
        user_id=user_id,
        created_at=now,
        expires_at=expires_at,
        last_seen_at=now,
        revoked_at=None,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    await session.insert()
    return session, raw_token


async def get_session_by_token(raw_token: str) -> Optional[BrowserSession]:
    """Look up active session using raw cookie token."""
    if not raw_token:
        return None
    token_hash = hash_token(raw_token)
    session = await BrowserSession.find_one(BrowserSession.session_hash == token_hash)
    if not session or not session.is_active:
        return None
    return session


async def touch_session(session: BrowserSession) -> None:
    """Update last_seen_at timestamp to track session freshness."""
    now = datetime.now(timezone.utc)
    last_seen = session.last_seen_at.replace(tzinfo=timezone.utc) if session.last_seen_at.tzinfo is None else session.last_seen_at
    # Only touch if last_seen_at was more than 60 seconds ago to avoid excessive DB writes
    if (now - last_seen).total_seconds() > 60:
        session.last_seen_at = now
        await session.save()


async def revoke_session(session_id: str, user_id: Optional[str] = None) -> bool:
    """Revoke a session by ID, optionally verifying ownership."""
    query = [BrowserSession.id == session_id]
    if user_id:
        query.append(BrowserSession.user_id == user_id)

    session = await BrowserSession.find_one(*query)
    if not session:
        return False

    session.revoked_at = datetime.now(timezone.utc)
    await session.save()
    return True


async def list_user_sessions(user_id: str) -> List[BrowserSession]:
    """List all non-revoked active sessions for a user."""
    sessions = await BrowserSession.find(
        BrowserSession.user_id == user_id,
        BrowserSession.revoked_at == None,
    ).sort(-BrowserSession.last_seen_at).to_list()
    return [s for s in sessions if s.is_active]
