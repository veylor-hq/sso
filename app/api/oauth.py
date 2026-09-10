"""OAuth 2.0 and OpenID Connect (OIDC) endpoints."""

import urllib.parse
from typing import Optional
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from app.config import get_settings
from app.dependencies.auth import (
    get_optional_user,
    get_user_from_bearer_token,
    require_session_user,
)
from app.dependencies.rate_limit import rate_limit_token
from app.models.user import User
from app.security.jwt import get_key_manager
from app.services.oauth import (
    OAuthError,
    create_authorization_code,
    exchange_authorization_code,
    get_client_by_id,
    validate_authorize_request,
)
from app.services.tokens import generate_tokens_for_authorization, get_oidc_claims_for_user

router = APIRouter(tags=["OAuth / OpenID Connect"])


@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OpenID Connect Discovery 1.0 endpoint."""
    settings = get_settings()
    issuer = settings.SSO_ISSUER.rstrip("/")

    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "picture",
        ],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
    }


@router.get("/.well-known/jwks.json")
async def jwks():
    """JSON Web Key Set (JWKS) endpoint publishing public keys for token verification."""
    km = get_key_manager()
    return km.get_jwks()


@router.get("/authorize")
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="openid profile email"),
    state: Optional[str] = Query(default=None),
    code_challenge: Optional[str] = Query(default=None),
    code_challenge_method: Optional[str] = Query(default=None),
    nonce: Optional[str] = Query(default=None),
    user: Optional[User] = Depends(get_optional_user),
):
    """OAuth 2.0 / OIDC Authorization Endpoint (Authorization Code Flow with PKCE)."""
    try:
        client, scopes = await validate_authorize_request(
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            request=request,
        )
    except OAuthError as e:
        # If redirect_uri is invalid or client is unknown, we MUST NOT redirect (per RFC 6749 Section 4.1.2.1)
        raise HTTPException(status_code=e.status_code, detail=f"{e.error}: {e.description}")

    # If the user does not have an active browser SSO session, redirect to login
    if not user:
        # Preserve original /authorize request URL in return_to parameter
        original_query = str(request.url.query)
        encoded_return = urllib.parse.quote(f"/authorize?{original_query}")
        return RedirectResponse(url=f"/login?return_to={encoded_return}", status_code=status.HTTP_302_FOUND)

    # User is authenticated!
    if user.authorized_apps is None:
        user.authorized_apps = []
    if client.client_id.lower() not in user.authorized_apps:
        user.authorized_apps.append(client.client_id.lower())
        await user.save()

    # Check if first-party trusted client
    if client.trusted:
        # First-party trusted client (e.g. eGarage, Relay, Pager, Warden)
        # Skip consent for standard scopes to enable frictionless SSO
        raw_code = await create_authorization_code(
            user_id=user.id,
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,  # type: ignore
            code_challenge_method=code_challenge_method or "S256",
            nonce=nonce,
        )
        # Build redirect back to client application with authorization code and state
        params = {"code": raw_code}
        if state:
            params["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        callback_url = f"{redirect_uri}{separator}{urllib.parse.urlencode(params)}"
        return RedirectResponse(url=callback_url, status_code=status.HTTP_302_FOUND)

    # Untrusted client: redirect to interactive consent screen
    consent_params = {
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    if state:
        consent_params["state"] = state
    if nonce:
        consent_params["nonce"] = nonce

    consent_url = f"/consent?{urllib.parse.urlencode(consent_params)}"
    return RedirectResponse(url=consent_url, status_code=status.HTTP_302_FOUND)


@router.post("/token", dependencies=[Depends(rate_limit_token)])
async def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    code_verifier: str = Form(...),
):
    """OAuth 2.0 Token Endpoint. Exchanges single-use authorization code + PKCE verifier for tokens."""
    if grant_type != "authorization_code":
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "unsupported_grant_type",
                "error_description": f"Grant type '{grant_type}' is not supported.",
            },
        )

    try:
        auth_code = await exchange_authorization_code(
            raw_code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
    except OAuthError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.error, "error_description": e.description},
        )

    from app.services.users import get_user_by_id
    user = await get_user_by_id(auth_code.user_id)
    if not user or user.disabled:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "invalid_grant",
                "error_description": "User account associated with authorization code is invalid or disabled.",
            },
        )

    if user.authorized_apps is None:
        user.authorized_apps = []
    if auth_code.client_id.lower() not in user.authorized_apps:
        user.authorized_apps.append(auth_code.client_id.lower())
        await user.save()

    token_data = generate_tokens_for_authorization(auth_code=auth_code, user=user)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=token_data,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@router.get("/userinfo")
async def userinfo(
    request: Request,
    user: User = Depends(get_user_from_bearer_token),
):
    """OpenID Connect UserInfo Endpoint. Requires valid Bearer access token with openid scope."""
    token_claims = getattr(request.state, "token_claims", {})
    scope_str = token_claims.get("scope", "")
    granted_scopes = [s.strip() for s in scope_str.split() if s.strip()]

    # OIDC Core 1.0 Section 5.3: UserInfo endpoint requires 'openid' scope
    if "openid" not in granted_scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access token missing required 'openid' scope.",
            headers={"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="openid"'},
        )

    # Return only claims corresponding to granted scopes
    claims = get_oidc_claims_for_user(user, scopes=granted_scopes)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=claims,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )
