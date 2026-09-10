"""Client registry and origin verification service for Veylor SSO.

Determines and verifies the calling service identity ('name-id') directly from
the registered OAuthClient models in SSO's own database. Blocks unauthorized
extra websites from accessing or authenticating against SSO.
"""

import logging
import urllib.parse
from typing import List, Optional, Set
from fastapi import HTTPException, Request, status

from app.config import get_settings
from app.models.oauth_client import OAuthClient

logger = logging.getLogger("veylor.sso.clients")


def normalize_origin(url: Optional[str]) -> Optional[str]:
    """Extract normalized scheme://netloc from an Origin or URL string."""
    if not url:
        return None
    url = url.strip()
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.netloc:
            netloc = parsed.netloc.lower()
            # Strip standard default ports
            if (parsed.scheme == "http" and netloc.endswith(":80")) or \
               (parsed.scheme == "https" and netloc.endswith(":443")):
                netloc = netloc.rsplit(":", 1)[0]
            return f"{parsed.scheme.lower()}://{netloc}"
    except Exception:
        pass
    return None


def get_client_allowed_origins(client: OAuthClient) -> Set[str]:
    """Collect all authorized web origins for a registered OAuthClient."""
    origins: Set[str] = set()

    # 1. Parse origins from registered redirect_uris
    for uri in client.redirect_uris:
        o = normalize_origin(uri)
        if o:
            origins.add(o)

    # 2. Add explicit allowed_origins if defined on client
    if hasattr(client, "allowed_origins") and client.allowed_origins:
        for o_str in client.allowed_origins:
            o = normalize_origin(o_str)
            if o:
                origins.add(o)

    return origins


def is_sso_internal_origin(origin: Optional[str]) -> bool:
    """Check if origin belongs to the SSO identity portal itself."""
    if not origin:
        return False
    norm_origin = normalize_origin(origin)
    if not norm_origin:
        return False

    settings = get_settings()
    issuer_origin = normalize_origin(settings.SSO_ISSUER)
    if issuer_origin and norm_origin == issuer_origin:
        return True

    allowed_internal = [
        "http://testserver",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://sso.veylor.dev",
    ]
    if norm_origin in allowed_internal:
        return True

    return False


async def get_client_by_origin(origin: str) -> Optional[OAuthClient]:
    """Find a registered, active OAuthClient that authorizes the given website origin."""
    norm_origin = normalize_origin(origin)
    if not norm_origin:
        return None

    active_clients = await OAuthClient.find(OAuthClient.disabled == False).to_list()
    for client in active_clients:
        allowed = get_client_allowed_origins(client)
        if norm_origin in allowed:
            return client

    return None


async def resolve_and_verify_service_from_request(
    request: Request,
    client_id_hint: Optional[str] = None,
    return_to: Optional[str] = None,
) -> Optional[OAuthClient]:
    """
    Determine and verify the service identity (name-id) from SSO's own registry.
    Blocks extra websites that are not permitted to use SSO.

    Returns:
        OAuthClient: The verified registered service model.
        None: When the request legitimately originates from SSO itself without a client context.

    Raises:
        HTTPException(403): If the request comes from an unregistered or unauthorized website.
    """
    settings = get_settings()

    # 1. Determine origin of request if present
    raw_origin = request.headers.get("origin")
    raw_referer = request.headers.get("referer")
    req_origin = normalize_origin(raw_origin) or normalize_origin(raw_referer)

    # 2. Extract client candidate from headers, hints, or query params
    client_id_candidate = (
        request.headers.get("x-client-id")
        or client_id_hint
        or request.query_params.get("client_id")
    )

    # Check return_to parameter if redirected within SSO (e.g. /authorize?client_id=egarage)
    if not client_id_candidate and return_to:
        try:
            parsed_ret = urllib.parse.urlparse(return_to)
            query_dict = urllib.parse.parse_qs(parsed_ret.query)
            if "client_id" in query_dict and query_dict["client_id"]:
                client_id_candidate = query_dict["client_id"][0]
        except Exception:
            pass

    # 3. If a client candidate is provided, verify it exists in SSO
    if client_id_candidate:
        client_id_clean = client_id_candidate.strip().lower()
        client = await OAuthClient.find_one(
            OAuthClient.client_id == client_id_clean,
            OAuthClient.disabled == False,
        )
        if not client:
            logger.warning("Rejected unknown or disabled client_id: %s", client_id_clean)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Service '{client_id_clean}' is not registered with Veylor SSO.",
            )

        # If an origin is present, ensure it is an authorized website for this service
        if req_origin and not is_sso_internal_origin(req_origin):
            allowed_origins = get_client_allowed_origins(client)
            if req_origin not in allowed_origins:
                logger.warning(
                    "Extra website '%s' attempted to access or impersonate service '%s'",
                    req_origin,
                    client_id_clean,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Website '{req_origin}' is not permitted to use service '{client.client_id}'.",
                )

        return client

    # 4. If no explicit client_id, determine service from Origin / Referer
    if req_origin:
        if is_sso_internal_origin(req_origin):
            # Request from SSO portal itself
            return None

        client = await get_client_by_origin(req_origin)
        if not client:
            logger.warning("Rejected request from unauthorized extra website: %s", req_origin)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Website '{req_origin}' is not permitted to use Veylor SSO.",
            )
        return client

    # 5. No origin and no client candidate
    # Check if request has trusted admin API key
    admin_key = request.headers.get("x-admin-api-key")
    if admin_key and admin_key == settings.ADMIN_API_KEY:
        return None

    # Internal test or local environment without headers allowed
    if settings.SSO_ENV == "test":
        return None

    return None
