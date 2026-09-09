"""Authentication and credential validation service."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from app.config import get_settings
from app.models.session import BrowserSession
from app.models.user import User
from app.models.token_records import ActionToken
from app.security.passwords import (
    hash_password,
    verify_password,
    needs_rehash,
    validate_password_complexity,
)
from app.security.random import generate_opaque_token, hash_token
from app.services.users import get_user_by_email, get_user_by_id

# Pre-computed dummy Argon2id hash used to normalize verification latency and eliminate user enumeration side-channels
_DUMMY_ARGON2_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQAAAAAAAAAAA$q114s88P6W7uXj2N+Z9y/gBv9mZ1"


async def authenticate_user(email: str, password: str) -> Tuple[Optional[User], Optional[str]]:
    """Verify user credentials. Returns (User, None) on success, or (None, error_reason) on failure."""
    user = await get_user_by_email(email)
    if not user:
        # Equalize execution timing to prevent email enumeration
        verify_password(password, _DUMMY_ARGON2_HASH)
        return None, "Invalid email or password."

    if user.disabled:
        return None, "This account has been disabled."

    if not verify_password(password, user.password_hash):
        return None, "Invalid email or password."

    # If hash needs upgrade (e.g. newer Argon2 parameters)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user.last_login_at = datetime.now(timezone.utc)
    await user.save()

    return user, None


async def create_password_reset_token(email: str) -> Optional[Tuple[User, str]]:
    """Create a short-lived password reset token.

    Stores only SHA-256 hash in DB. Returns (user, plaintext_token).
    """
    settings = get_settings()
    user = await get_user_by_email(email)
    if not user or user.disabled:
        return None

    raw_token = generate_opaque_token(32)
    token_h = hash_token(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.PASSWORD_RESET_TTL_SECONDS)

    action_token = ActionToken(
        token_hash=token_h,
        user_id=user.id,
        token_type="password_reset",
        expires_at=expires_at,
        used_at=None,
        created_at=now,
    )
    await action_token.insert()
    return user, raw_token


async def reset_password_with_token(raw_token: str, new_password: str) -> Tuple[bool, str]:
    """Validate token and reset user's password."""
    is_valid, msg = validate_password_complexity(new_password)
    if not is_valid:
        return False, msg

    token_h = hash_token(raw_token)
    action_token = await ActionToken.find_one(
        ActionToken.token_hash == token_h,
        ActionToken.token_type == "password_reset",
    )

    if not action_token or not action_token.is_valid:
        return False, "Password reset token is invalid or has expired."

    user = await get_user_by_id(action_token.user_id)
    if not user:
        return False, "User account not found."

    now = datetime.now(timezone.utc)
    user.password_hash = hash_password(new_password)
    user.updated_at = now
    await user.save()

    # Invalidate all active browser sessions to kick out attackers and terminate compromised sessions
    await BrowserSession.find(
        BrowserSession.user_id == user.id,
        BrowserSession.revoked_at == None,
    ).update({"$set": {"revoked_at": now}})

    action_token.used_at = now
    await action_token.save()

    return True, "Password has been successfully reset."


async def create_email_verification_token(user_id: str) -> str:
    """Create a short-lived email verification token."""
    settings = get_settings()
    raw_token = generate_opaque_token(32)
    token_h = hash_token(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.EMAIL_VERIFICATION_TTL_SECONDS)

    action_token = ActionToken(
        token_hash=token_h,
        user_id=user_id,
        token_type="email_verification",
        expires_at=expires_at,
        used_at=None,
        created_at=now,
    )
    await action_token.insert()
    return raw_token


async def verify_email_with_token(raw_token: str) -> Tuple[bool, str]:
    """Validate email verification token and update user's email_verified flag."""
    token_h = hash_token(raw_token)
    action_token = await ActionToken.find_one(
        ActionToken.token_hash == token_h,
        ActionToken.token_type == "email_verification",
    )

    if not action_token or not action_token.is_valid:
        return False, "Email verification token is invalid or has expired."

    user = await get_user_by_id(action_token.user_id)
    if not user:
        return False, "User account not found."

    user.email_verified = True
    user.updated_at = datetime.now(timezone.utc)
    await user.save()

    action_token.used_at = datetime.now(timezone.utc)
    await action_token.save()

    return True, "Email has been successfully verified."


async def resend_email_verification(email: str) -> Tuple[bool, Optional[str]]:
    """Look up user by email and issue a new verification token if unverified."""
    user = await get_user_by_email(email)
    if not user or user.email_verified:
        return False, None
    token = await create_email_verification_token(user.id)
    return True, token
