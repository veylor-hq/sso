"""Business logic services for Veylor SSO."""

from app.services.users import get_user_by_id, get_user_by_email, create_user, update_user_profile
from app.services.sessions import create_session, get_session_by_token, touch_session, revoke_session, list_user_sessions
from app.services.authentication import (
    authenticate_user,
    create_password_reset_token,
    reset_password_with_token,
    create_email_verification_token,
    verify_email_with_token,
)
from app.services.oauth import (
    OAuthError,
    get_client_by_id,
    validate_authorize_request,
    create_authorization_code,
    exchange_authorization_code,
)
from app.services.tokens import generate_tokens_for_authorization, get_oidc_claims_for_user
from app.services.email import send_verification_email, send_password_reset_email

__all__ = [
    "get_user_by_id",
    "get_user_by_email",
    "create_user",
    "update_user_profile",
    "create_session",
    "get_session_by_token",
    "touch_session",
    "revoke_session",
    "list_user_sessions",
    "authenticate_user",
    "create_password_reset_token",
    "reset_password_with_token",
    "create_email_verification_token",
    "verify_email_with_token",
    "OAuthError",
    "get_client_by_id",
    "validate_authorize_request",
    "create_authorization_code",
    "exchange_authorization_code",
    "generate_tokens_for_authorization",
    "get_oidc_claims_for_user",
    "send_verification_email",
    "send_password_reset_email",
]
