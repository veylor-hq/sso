"""Proof Key for Code Exchange (PKCE) RFC 7636 implementation."""

import base64
import hashlib
import re
import secrets
from app.security.random import constant_time_compare

# Code verifier character set: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
PKCE_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def generate_code_verifier(length: int = 64) -> str:
    """Generate a random PKCE code verifier (43 to 128 characters)."""
    if not (43 <= length <= 128):
        raise ValueError("PKCE code_verifier length must be between 43 and 128 characters.")
    # urlsafe characters without padding
    token = secrets.token_urlsafe(96)
    # Strip any potential padding or non-spec characters, slice to length
    cleaned = re.sub(r"[^A-Za-z0-9\-._~]", "", token)
    return cleaned[:length]


def compute_code_challenge(verifier: str) -> str:
    """Compute S256 code challenge from code_verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_pkce(code_verifier: str, stored_challenge: str, method: str = "S256") -> bool:
    """Verify PKCE code_verifier against stored code_challenge."""
    if method != "S256":
        return False

    if not code_verifier or not PKCE_VERIFIER_PATTERN.match(code_verifier):
        return False

    computed = compute_code_challenge(code_verifier)
    return constant_time_compare(computed, stored_challenge)
