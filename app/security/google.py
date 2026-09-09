"""Google OAuth2 token verification utilities."""

import logging
from typing import Any, Dict, Optional
import httpx
import jwt
from jwt import PyJWKClient
from app.config import get_settings

logger = logging.getLogger("veylor.google")

GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"]

_jwks_client: Optional[PyJWKClient] = None


def get_google_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(GOOGLE_CERTS_URL, cache_keys=True, lifespan=3600)
    return _jwks_client


async def verify_google_id_token(token_str: str) -> Optional[Dict[str, Any]]:
    """Verify a Google ID token and return verified claims, or None if invalid."""
    settings = get_settings()
    expected_aud = settings.GOOGLE_CLIENT_ID

    # Path 1: Local verification using Google's published JWKS
    try:
        jwks = get_google_jwks_client()
        signing_key = jwks.get_signing_key_from_jwt(token_str)
        claims = jwt.decode(
            token_str,
            signing_key.key,
            algorithms=["RS256"],
            audience=expected_aud,
            issuer=GOOGLE_ISSUERS,
            options={"verify_exp": True},
        )
        if claims.get("email"):
            return claims
    except Exception as e:
        logger.debug("Local Google JWKS validation failed, trying tokeninfo endpoint: %s", e)

    # Path 2: Fallback to Google's tokeninfo API endpoint
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(GOOGLE_TOKENINFO_URL, params={"id_token": token_str})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("aud") == expected_aud and data.get("iss") in GOOGLE_ISSUERS:
                    if data.get("email"):
                        return data
            logger.warning("Google tokeninfo rejected token: %s", resp.text)
    except Exception as e:
        logger.error("Error connecting to Google tokeninfo: %s", e)

    return None
