"""Rate limit dependency helpers for endpoints."""

from fastapi import HTTPException, Request, status
from app.config import get_settings
from app.security.rate_limit import check_rate_limit, get_client_ip


async def rate_limit_login(request: Request):
    """Enforce rate limits on login attempts by IP."""
    settings = get_settings()
    ip = get_client_ip(request)
    allowed = await check_rate_limit(
        key=f"login:{ip}",
        max_requests=settings.RATE_LIMIT_LOGIN_PER_MINUTE,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again in a minute.",
        )


async def rate_limit_register(request: Request):
    """Enforce rate limits on registration attempts by IP."""
    ip = get_client_ip(request)
    allowed = await check_rate_limit(
        key=f"register:{ip}",
        max_requests=10,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again in a minute.",
        )


async def rate_limit_forgot_password(request: Request):
    """Enforce rate limits on password reset and verification emails."""
    ip = get_client_ip(request)
    allowed = await check_rate_limit(
        key=f"forgot_pw:{ip}",
        max_requests=10,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please slow down.",
        )


async def rate_limit_token(request: Request):
    """Enforce rate limits on OAuth /token endpoint."""
    settings = get_settings()
    ip = get_client_ip(request)
    allowed = await check_rate_limit(
        key=f"token:{ip}",
        max_requests=settings.RATE_LIMIT_TOKEN_PER_MINUTE,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many token requests. Please slow down.",
        )
