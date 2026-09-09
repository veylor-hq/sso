"""Tests for Authentication endpoints and sessions."""

import pytest
from datetime import datetime, timedelta, timezone
from app.models.session import BrowserSession
from app.models.user import User
from app.security.random import hash_token
from app.services.users import get_user_by_email


@pytest.mark.asyncio
async def test_registration_successful(client):
    """Test standard user registration."""
    payload = {
        "email": "mechanic@egarage.uk",
        "password": "SecurePassword123!",
        "name": "Jane Doe",
    }
    response = await client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "mechanic@egarage.uk"
    assert data["name"] == "Jane Doe"
    assert data["id"].startswith("usr_")
    assert data["email_verified"] is False
    assert "password" not in data
    assert "password_hash" not in data

    # Verify session cookie was set
    assert "veylor_session" in response.cookies

    # Verify user exists in database and password is not plaintext
    user = await get_user_by_email("mechanic@egarage.uk")
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    assert "SecurePassword123!" not in user.password_hash


@pytest.mark.asyncio
async def test_registration_duplicate_email(client):
    """Test duplicate email rejection (case-insensitive)."""
    payload = {
        "email": "duplicate@veylor.dev",
        "password": "Password123!",
        "name": "First User",
    }
    r1 = await client.post("/api/auth/register", json=payload)
    assert r1.status_code == 201

    # Try registering again with different casing
    payload["email"] = "DUPLICATE@veylor.dev"
    r2 = await client.post("/api/auth/register", json=payload)
    assert r2.status_code == 400
    assert "already exists" in r2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_login_successful_and_incorrect_password(client):
    """Test login with correct and incorrect credentials."""
    reg_payload = {
        "email": "login_test@veylor.dev",
        "password": "MySecretPassword123!",
        "name": "Login User",
    }
    await client.post("/api/auth/register", json=reg_payload)

    # Incorrect password
    bad_login = await client.post(
        "/api/auth/login",
        json={"email": "login_test@veylor.dev", "password": "WrongPassword!"},
    )
    assert bad_login.status_code == 401
    assert "veylor_session" not in bad_login.cookies

    # Correct password
    good_login = await client.post(
        "/api/auth/login",
        json={"email": "login_test@veylor.dev", "password": "MySecretPassword123!"},
    )
    assert good_login.status_code == 200
    assert "veylor_session" in good_login.cookies


@pytest.mark.asyncio
async def test_login_disabled_account(client):
    """Test that disabled accounts cannot authenticate."""
    reg = await client.post(
        "/api/auth/register",
        json={"email": "disabled@veylor.dev", "password": "Password123!", "name": "Disabled"},
    )
    assert reg.status_code == 201
    user_id = reg.json()["id"]

    # Disable the user account
    user = await User.find_one(User.id == user_id)
    user.disabled = True
    await user.save()

    # Attempt login
    login_resp = await client.post(
        "/api/auth/login",
        json={"email": "disabled@veylor.dev", "password": "Password123!"},
    )
    assert login_resp.status_code == 401
    assert "disabled" in login_resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_logout_and_session_revocation(client):
    """Test that logging out revokes the session and clears cookies."""
    reg = await client.post(
        "/api/auth/register",
        json={"email": "logout_test@veylor.dev", "password": "Password123!", "name": "Logout User"},
    )
    session_cookie = reg.cookies.get("veylor_session")
    assert session_cookie is not None

    # Access protected /api/auth/me
    me_resp = await client.get("/api/auth/me", cookies={"veylor_session": session_cookie})
    assert me_resp.status_code == 200

    # Logout
    logout_resp = await client.post("/api/auth/logout", cookies={"veylor_session": session_cookie})
    assert logout_resp.status_code == 200

    # Attempting to access /api/auth/me should now fail
    me_after = await client.get("/api/auth/me", cookies={"veylor_session": session_cookie})
    assert me_after.status_code == 401


@pytest.mark.asyncio
async def test_session_expiration(client):
    """Test that expired sessions are rejected."""
    reg = await client.post(
        "/api/auth/register",
        json={"email": "expire_test@veylor.dev", "password": "Password123!", "name": "Expire User"},
    )
    session_cookie = reg.cookies.get("veylor_session")
    cookie_hash = hash_token(session_cookie)

    # Fast-forward session expiration into the past
    session = await BrowserSession.find_one(BrowserSession.session_hash == cookie_hash)
    session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    await session.save()

    # Request should be rejected as expired
    resp = await client.get("/api/auth/me", cookies={"veylor_session": session_cookie})
    assert resp.status_code == 401
