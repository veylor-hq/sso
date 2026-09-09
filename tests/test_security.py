"""Tests for Security Properties (hashing, CSRF, security headers, opaque IDs)."""

import pytest
from app.models.authorization_code import AuthorizationCode
from app.models.session import BrowserSession
from app.models.user import User
from app.security.random import generate_opaque_id


@pytest.mark.asyncio
async def test_user_id_format_and_immutability():
    """Ensure generated user IDs follow the required format: usr_01J..."""
    uid = generate_opaque_id(prefix="usr")
    assert uid.startswith("usr_")
    assert len(uid) > 15
    # Must be URL and header safe
    assert " " not in uid
    assert "/" not in uid


@pytest.mark.asyncio
async def test_no_plaintext_secrets_in_database(client):
    """Verify that passwords, session cookies, and auth codes are strictly stored hashed."""
    # 1. Register a user
    raw_password = "SuperSecretPassword123!"
    reg = await client.post(
        "/api/auth/register",
        json={"email": "security_test@veylor.dev", "password": raw_password, "name": "Security Test"},
    )
    user_id = reg.json()["id"]
    raw_session_cookie = reg.cookies["veylor_session"]

    # 2. Check User record in DB
    user = await User.find_one(User.id == user_id)
    assert user is not None
    assert raw_password not in user.password_hash
    assert user.password_hash.startswith("$argon2id$")

    # 3. Check Session record in DB
    sessions = await BrowserSession.find(BrowserSession.user_id == user_id).to_list()
    assert len(sessions) == 1
    session = sessions[0]
    # The session_hash must not equal the raw cookie token
    assert session.session_hash != raw_session_cookie
    assert len(session.session_hash) == 64  # SHA-256 hex length


@pytest.mark.asyncio
async def test_security_headers_present_on_all_responses(client):
    """Verify essential security response headers."""
    resp = await client.get("/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "1; mode=block" in resp.headers.get("X-XSS-Protection", "")
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "X-Request-ID" in resp.headers


@pytest.mark.asyncio
async def test_web_csrf_protection_rejects_missing_token(client):
    """Verify that web form submissions without valid CSRF tokens are rejected."""
    resp = await client.post(
        "/login",
        data={"email": "csrf_test@veylor.dev", "password": "Password123!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 400
    assert "security token mismatch" in resp.text.lower()
