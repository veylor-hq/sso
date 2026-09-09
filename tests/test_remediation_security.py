"""Automated regression tests for Veylor SSO security remediations."""

import pytest
from app.models.authorization_code import AuthorizationCode
from app.models.session import BrowserSession
from app.models.user import User
from app.security.google import verify_google_id_token
from app.security.jwt import create_id_token, create_access_token
from app.services.authentication import create_password_reset_token, reset_password_with_token
from app.services.sessions import create_session
from app.services.users import create_user


@pytest.mark.asyncio
async def test_protocol_relative_open_redirect_rejected(client):
    """Ensure protocol-relative URLs (//evil.com) are rejected on login redirect."""
    resp = await client.get("/login?return_to=//evil.com")
    assert resp.status_code == 200

    # Submit login with malicious return_to
    user = await create_user(
        email="redirect_test@veylor.dev",
        password="ValidPassword123!",
        name="Redirect Test",
    )
    user.email_verified = True
    await user.save()

    # Set explicit CSRF token
    csrf_token = "valid_test_csrf_token_value_123"
    client.cookies.set("veylor_csrf", csrf_token)

    login_post = await client.post(
        "/login",
        data={
            "email": "redirect_test@veylor.dev",
            "password": "ValidPassword123!",
            "return_to": "//evil.com/phishing",
            "csrf_token": csrf_token,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert login_post.status_code == 302
    # Must redirect to default /account instead of //evil.com
    assert login_post.headers["Location"] == "/account"


@pytest.mark.asyncio
async def test_unverified_google_id_token_rejected():
    """Ensure Google ID tokens with email_verified=False are strictly rejected."""
    import jwt
    from app.config import get_settings
    settings = get_settings()

    unverified_claims = {
        "iss": "https://accounts.google.com",
        "aud": settings.GOOGLE_CLIENT_ID,
        "sub": "google_12345",
        "email": "victim@example.com",
        "email_verified": False,
    }
    dummy_jwt = jwt.encode(unverified_claims, "secret", algorithm="HS256")
    result = await verify_google_id_token(dummy_jwt)
    assert result is None


@pytest.mark.asyncio
async def test_unverified_admin_email_cannot_access_admin_api(client):
    """Ensure a user registering an admin email without verifying cannot gain admin privileges."""
    admin_email = "csigorek@gmail.com"
    user = await create_user(
        email=admin_email,
        password="Password1234!",
        name="Unverified Impersonator",
    )
    assert user.email_verified is False

    # Establish session
    _, raw_token = await create_session(user_id=user.id)
    client.cookies.set("veylor_session", raw_token)

    # Attempt to access protected admin endpoint
    resp = await client.get("/api/admin/insights")
    assert resp.status_code == 403
    assert "Administrator privilege required" in resp.text


@pytest.mark.asyncio
async def test_sessions_revoked_on_password_reset():
    """Ensure all active browser sessions are invalidated when a password reset occurs."""
    user = await create_user(
        email="reset_session_test@veylor.dev",
        password="OldPassword123!",
        name="Reset Test",
    )
    user.email_verified = True
    await user.save()

    # Create 2 active sessions
    ses1, _ = await create_session(user_id=user.id)
    ses2, _ = await create_session(user_id=user.id)
    assert ses1.is_active is True
    assert ses2.is_active is True

    # Generate password reset token
    res = await create_password_reset_token(user.email)
    assert res is not None
    _, raw_token = res

    # Reset password
    success, msg = await reset_password_with_token(raw_token, "NewPassword123!")
    assert success is True

    # Verify both sessions were revoked
    refreshed_ses1 = await BrowserSession.find_one(BrowserSession.id == ses1.id)
    refreshed_ses2 = await BrowserSession.find_one(BrowserSession.id == ses2.id)
    assert refreshed_ses1.revoked_at is not None
    assert refreshed_ses2.revoked_at is not None
    assert refreshed_ses1.is_active is False
    assert refreshed_ses2.is_active is False


@pytest.mark.asyncio
async def test_id_token_rejected_as_access_token_at_userinfo(client):
    """Ensure ID tokens cannot be accepted as access tokens (token type confusion mitigation)."""
    user = await create_user(
        email="token_type_test@veylor.dev",
        password="Password123!",
        name="Token Type Test",
    )
    # Create an ID token (typ: JWT)
    id_token = create_id_token(sub=user.id, aud="egarage")

    # Present ID token as Bearer token to /userinfo
    resp = await client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {id_token}"},
    )
    assert resp.status_code == 401
    assert "Invalid access token" in resp.text


@pytest.mark.asyncio
async def test_userinfo_requires_openid_scope(client):
    """Ensure /userinfo enforces that the access token has 'openid' scope."""
    user = await create_user(
        email="scope_test@veylor.dev",
        password="Password123!",
        name="Scope Test",
    )
    # Create an access token with only 'relay:read' scope (no openid)
    access_token = create_access_token(
        sub=user.id,
        client_id="relay",
        scopes=["relay:read"],
    )

    resp = await client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403
    assert "openid" in resp.text


@pytest.mark.asyncio
async def test_security_csp_header_present(client):
    """Ensure Content-Security-Policy header is returned."""
    resp = await client.get("/health")
    assert "Content-Security-Policy" in resp.headers
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


@pytest.mark.asyncio
async def test_terms_and_privacy_pages_accessible(client):
    """Ensure /terms and /privacy pages render successfully with expected legal terms."""
    terms_resp = await client.get("/terms")
    assert terms_resp.status_code == 200
    assert "Terms of Service" in terms_resp.text
    assert "Veylor Systems" in terms_resp.text
    assert "eGarage" in terms_resp.text

    privacy_resp = await client.get("/privacy")
    assert privacy_resp.status_code == 200
    assert "Privacy Policy" in privacy_resp.text
    assert "UK GDPR" in privacy_resp.text
    assert "Data Controller" in privacy_resp.text

