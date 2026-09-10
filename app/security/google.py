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

GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
_jwks_client: Optional[PyJWKClient] = None


def get_google_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(GOOGLE_CERTS_URL, cache_keys=True, lifespan=3600)
    return _jwks_client


def _is_email_verified(claims: Dict[str, Any]) -> bool:
    verified = claims.get("email_verified")
    if isinstance(verified, bool):
        return verified
    if isinstance(verified, str):
        return verified.lower() == "true"
    return False


async def verify_google_id_token(token_str: str) -> Optional[Dict[str, Any]]:
    """Verify a Google ID token and return verified claims, or None if invalid.
    
    Strictly enforces that Google has verified the email address to prevent account takeover.
    """
    settings = get_settings()
    allowed_auds = settings.get_allowed_google_client_ids()

    # Path 1: Local verification using Google's published JWKS
    try:
        jwks = get_google_jwks_client()
        signing_key = jwks.get_signing_key_from_jwt(token_str)
        claims = jwt.decode(
            token_str,
            signing_key.key,
            algorithms=["RS256"],
            audience=allowed_auds,
            issuer=GOOGLE_ISSUERS,
            options={"verify_exp": True},
        )
        if claims.get("email") and _is_email_verified(claims):
            return claims
        if claims.get("email") and not _is_email_verified(claims):
            logger.warning("Rejected Google ID token: email is unverified (%s)", claims.get("email"))
            return None
    except Exception as e:
        logger.debug("Local Google JWKS validation failed, trying tokeninfo endpoint: %s", e)

    # Path 2: Fallback to Google's tokeninfo API endpoint
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(GOOGLE_TOKENINFO_URL, params={"id_token": token_str})
            if resp.status_code == 200:
                data = resp.json()
                if (data.get("aud") in allowed_auds or not allowed_auds) and data.get("iss") in GOOGLE_ISSUERS:
                    if data.get("email") and _is_email_verified(data):
                        return data
                    if data.get("email") and not _is_email_verified(data):
                        logger.warning("Rejected Google tokeninfo: email is unverified (%s)", data.get("email"))
                        return None
            logger.warning("Google tokeninfo rejected token: %s", resp.text)
    except Exception as e:
        logger.error("Error connecting to Google tokeninfo: %s", e)

    return None


async def verify_google_access_token(access_token: str) -> Optional[Dict[str, Any]]:
    """Verify Google access token by querying Google's userinfo endpoint."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("email") and _is_email_verified(data):
                    return data
                if data.get("email") and not _is_email_verified(data):
                    logger.warning("Rejected Google access token: email is unverified (%s)", data.get("email"))
                    return None
            logger.warning("Google userinfo rejected access token: %s", resp.text)
    except Exception as e:
        logger.error("Error connecting to Google userinfo: %s", e)
    return None
