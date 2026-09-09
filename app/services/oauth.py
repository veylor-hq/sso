"""OAuth 2.0 and OpenID Connect authorization code and client validation service."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from app.config import get_settings
from app.models.authorization_code import AuthorizationCode
from app.models.oauth_client import OAuthClient
from app.security.pkce import verify_pkce
from app.security.random import generate_opaque_token, hash_token


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status_code: int = 400):
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


async def get_client_by_id(client_id: str) -> Optional[OAuthClient]:
    """Retrieve an OAuth client by its unique client_id."""
    return await OAuthClient.find_one(OAuthClient.client_id == client_id)


async def validate_authorize_request(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
) -> Tuple[OAuthClient, List[str]]:
    """Validate incoming /authorize parameters strictly according to OAuth 2.0 & OIDC specs."""
    # 1. Validate response_type
    if response_type != "code":
        raise OAuthError(
            "unsupported_response_type",
            f"Response type '{response_type}' is not supported. Only 'code' is allowed.",
        )

    # 2. Validate client
    if not client_id:
        raise OAuthError("invalid_request", "Missing client_id parameter.")

    client = await get_client_by_id(client_id)
    if not client or client.disabled:
        raise OAuthError("unauthorized_client", f"Client '{client_id}' is unknown or disabled.")

    # 3. Exact redirect_uri matching
    if not redirect_uri:
        raise OAuthError("invalid_request", "Missing redirect_uri parameter.")

    if redirect_uri not in client.redirect_uris:
        raise OAuthError(
            "invalid_request",
            f"The redirect_uri does not match any registered URIs for client '{client_id}'.",
        )

    # In production, require HTTPS (allow HTTP for localhost in dev)
    if redirect_uri.startswith("http://") and not (
        "://localhost" in redirect_uri or "://127.0.0.1" in redirect_uri
    ):
        settings = get_settings()
        if settings.SSO_ENV == "production":
            raise OAuthError(
                "invalid_request",
                "Non-HTTPS redirect URIs are not permitted in production.",
            )

    # 4. Validate PKCE parameters (PKCE is mandatory with S256)
    if not code_challenge:
        raise OAuthError(
            "invalid_request",
            "PKCE code_challenge is required for all authorization requests.",
        )

    if code_challenge_method != "S256":
        raise OAuthError(
            "invalid_request",
            "Only 'S256' code_challenge_method is supported.",
        )

    # 5. Parse and validate scopes
    requested_scopes = [s.strip() for s in scope.split() if s.strip()]
    if not requested_scopes:
        requested_scopes = ["openid"]

    for sc in requested_scopes:
        if sc not in client.allowed_scopes:
            raise OAuthError(
                "invalid_scope",
                f"Scope '{sc}' is not allowed for client '{client_id}'.",
            )

    return client, requested_scopes


async def create_authorization_code(
    user_id: str,
    client_id: str,
    redirect_uri: str,
    scopes: List[str],
    code_challenge: str,
    code_challenge_method: str = "S256",
    nonce: Optional[str] = None,
) -> str:
    """Generate a single-use authorization code and store its hash."""
    settings = get_settings()
    raw_code = generate_opaque_token(32)
    code_h = hash_token(raw_code)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.AUTHORIZATION_CODE_TTL_SECONDS)

    auth_code = AuthorizationCode(
        code_hash=code_h,
        user_id=user_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        created_at=now,
        expires_at=expires_at,
        used_at=None,
    )
    await auth_code.insert()
    return raw_code


async def exchange_authorization_code(
    raw_code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> AuthorizationCode:
    """Validate authorization code, prevent replay, verify PKCE challenge, and invalidate code."""
    if not raw_code:
        raise OAuthError("invalid_request", "Missing authorization code.")

    code_h = hash_token(raw_code)
    auth_code = await AuthorizationCode.find_one(AuthorizationCode.code_hash == code_h)

    if not auth_code:
        raise OAuthError("invalid_grant", "Authorization code not found or invalid.")

    # Replay detection: if code was already used, reject immediately
    if auth_code.used_at is not None:
        raise OAuthError(
            "invalid_grant",
            "Authorization code has already been used (replay detected).",
        )

    # Check expiration
    now = datetime.now(timezone.utc)
    exp = auth_code.expires_at.replace(tzinfo=timezone.utc) if auth_code.expires_at.tzinfo is None else auth_code.expires_at
    if exp <= now:
        raise OAuthError("invalid_grant", "Authorization code has expired.")

    # Invalidate code immediately to prevent concurrent replay
    auth_code.used_at = now
    await auth_code.save()

    # Verify client match
    if auth_code.client_id != client_id:
        raise OAuthError(
            "invalid_grant",
            "Authorization code was not issued to this client.",
        )

    # Verify redirect_uri match
    if auth_code.redirect_uri != redirect_uri:
        raise OAuthError(
            "invalid_grant",
            "Redirect URI does not match the URI used in the authorization request.",
        )

    # Verify PKCE S256
    if not code_verifier:
        raise OAuthError("invalid_grant", "Missing code_verifier for PKCE validation.")

    if not verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
        raise OAuthError("invalid_grant", "PKCE code_verifier does not match code_challenge.")

    return auth_code
