"""CSRF protection using secure double-submit cookie / HMAC token."""

import hmac
import hashlib
import time
from typing import Optional
from fastapi import Request, HTTPException, status
from app.config import get_settings
from app.security.random import constant_time_compare, generate_opaque_token

CSRF_COOKIE_NAME = "veylor_csrf"


def generate_csrf_token() -> str:
    """Generate a random CSRF token."""
    return generate_opaque_token(24)


def verify_csrf_token(request: Request, submitted_token: Optional[str]) -> bool:
    """Verify submitted CSRF token against CSRF cookie."""
    if not submitted_token:
        return False
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token:
        return False
    return constant_time_compare(cookie_token, submitted_token)
