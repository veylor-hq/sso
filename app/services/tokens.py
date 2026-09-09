"""Token generation and OIDC claims mapping service."""

from typing import Any, Dict, List
from app.config import get_settings
from app.models.authorization_code import AuthorizationCode
from app.models.user import User
from app.security.jwt import create_access_token, create_id_token


def get_oidc_claims_for_user(user: User, scopes: List[str]) -> Dict[str, Any]:
    """Build OIDC claims dict according to requested scopes."""
    claims: Dict[str, Any] = {
        "sub": user.id,  # Immutable opaque Veylor ID (usr_01J...)
    }

    if "profile" in scopes:
        claims["name"] = user.name
        if user.given_name:
            claims["given_name"] = user.given_name
        if user.family_name:
            claims["family_name"] = user.family_name
        if user.avatar_url:
            claims["picture"] = user.avatar_url

    if "email" in scopes:
        claims["email"] = user.email
        claims["email_verified"] = user.email_verified

    return claims


def generate_tokens_for_authorization(
    auth_code: AuthorizationCode,
    user: User,
) -> Dict[str, Any]:
    """Generate access_token, id_token, token_type, expires_in, and scope."""
    settings = get_settings()
    scopes = auth_code.scopes

    # 1. Generate Access Token
    access_token = create_access_token(
        sub=user.id,
        client_id=auth_code.client_id,
        scopes=scopes,
        aud=auth_code.client_id,
        ttl_seconds=settings.ACCESS_TOKEN_TTL_SECONDS,
    )

    # 2. Generate OIDC ID Token if 'openid' is requested
    id_token = None
    if "openid" in scopes:
        id_claims = get_oidc_claims_for_user(user, scopes)
        id_token = create_id_token(
            sub=user.id,
            aud=auth_code.client_id,
            claims=id_claims,
            nonce=auth_code.nonce,
            ttl_seconds=settings.ID_TOKEN_TTL_SECONDS,
        )

    response: Dict[str, Any] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_TTL_SECONDS,
        "scope": " ".join(scopes),
    }

    if id_token:
        response["id_token"] = id_token

    return response
