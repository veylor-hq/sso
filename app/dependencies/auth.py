"""Authentication dependencies for FastAPI routes."""

from typing import Optional
from fastapi import Cookie, Depends, Header, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.config import get_settings
from app.models.session import BrowserSession
from app.models.user import User
from app.security.jwt import decode_and_verify_token
from app.security.random import constant_time_compare
from app.services.sessions import get_session_by_token, touch_session
from app.services.users import get_user_by_id

bearer_scheme = HTTPBearer(auto_error=False)


async def get_optional_session(
    request: Request,
) -> Optional[BrowserSession]:
    """Retrieve active session from cookie if present."""
    settings = get_settings()
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not cookie_token:
        return None

    session = await get_session_by_token(cookie_token)
    if session:
        await touch_session(session)
    return session


async def get_optional_user(
    session: Optional[BrowserSession] = Depends(get_optional_session),
) -> Optional[User]:
    """Retrieve User corresponding to the current session."""
    if not session:
        return None
    user = await get_user_by_id(session.user_id)
    if not user or user.disabled:
        return None
    return user


async def require_session_user(
    user: Optional[User] = Depends(get_optional_user),
) -> User:
    """Require an authenticated user from a valid browser session."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


async def get_user_from_bearer_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> User:
    """Validate Bearer access token and return associated User for resource/userinfo endpoints."""
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_and_verify_token(credentials.credentials)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid access token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token sub claim missing",
        )

    user = await get_user_by_id(user_id)
    if not user or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account does not exist or is disabled",
        )

    return user


async def require_admin_key(
    x_admin_api_key: Optional[str] = Header(None, alias="X-Admin-API-Key"),
) -> bool:
    """Validate admin API key header."""
    settings = get_settings()
    if not x_admin_api_key or not constant_time_compare(x_admin_api_key, settings.ADMIN_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Invalid Admin API Key",
        )
    return True


async def require_admin_user(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    x_admin_api_key: Optional[str] = Header(None, alias="X-Admin-API-Key"),
) -> Optional[User]:
    """Require an admin either via active session (is_admin or email in ADMIN_EMAILS) or Admin API Key."""
    settings = get_settings()

    # Path 1: API key in header, query param, or admin session cookie
    api_key = (
        x_admin_api_key
        or request.query_params.get("admin_key")
        or request.cookies.get("veylor_admin_key")
    )
    if api_key and constant_time_compare(api_key, settings.ADMIN_API_KEY):
        return user

    # Path 2: Authenticated user with admin status
    if user:
        admin_emails = [e.lower() for e in settings.ADMIN_EMAILS]
        if user.is_admin or user.email.lower() in admin_emails:
            return user

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Administrator privilege required",
    )

