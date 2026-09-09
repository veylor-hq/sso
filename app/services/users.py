"""User identity management service."""

from datetime import datetime, timezone
from typing import Optional
from app.models.user import User
from app.security.passwords import hash_password, validate_password_complexity
from app.security.random import generate_opaque_id


async def get_user_by_id(user_id: str) -> Optional[User]:
    """Retrieve user by immutable opaque ID."""
    return await User.find_one(User.id == user_id)


async def get_user_by_email(email: str) -> Optional[User]:
    """Retrieve user by normalized lowercase email."""
    return await User.find_one(User.email == email.strip().lower())


async def create_user(
    email: str,
    password: str,
    name: str,
    given_name: Optional[str] = None,
    family_name: Optional[str] = None,
) -> User:
    """Create a new Veylor account with an immutable opaque ID."""
    norm_email = email.strip().lower()

    # Check for existing account
    existing = await get_user_by_email(norm_email)
    if existing:
        raise ValueError("An account with this email already exists.")

    is_valid, msg = validate_password_complexity(password)
    if not is_valid:
        raise ValueError(msg)

    # If given_name or family_name are not provided, derive from name
    if not given_name and " " in name:
        parts = name.strip().split(" ", 1)
        given_name = parts[0]
        if not family_name and len(parts) > 1:
            family_name = parts[1]

    # Generate immutable opaque ID: usr_01J...
    user_id = generate_opaque_id(prefix="usr")
    pw_hash = hash_password(password)

    now = datetime.now(timezone.utc)
    user = User(
        id=user_id,
        email=norm_email,
        email_verified=False,
        password_hash=pw_hash,
        name=name.strip(),
        given_name=given_name.strip() if given_name else None,
        family_name=family_name.strip() if family_name else None,
        disabled=False,
        created_at=now,
        updated_at=now,
    )
    await user.insert()
    return user


async def update_user_profile(
    user: User,
    name: Optional[str] = None,
    given_name: Optional[str] = None,
    family_name: Optional[str] = None,
    avatar_url: Optional[str] = None,
) -> User:
    """Update user profile fields."""
    if name is not None:
        user.name = name.strip()
    if given_name is not None:
        user.given_name = given_name.strip() or None
    if family_name is not None:
        user.family_name = family_name.strip() or None
    if avatar_url is not None:
        user.avatar_url = avatar_url.strip() or None

    user.updated_at = datetime.now(timezone.utc)
    await user.save()
    return user
