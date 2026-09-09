"""Tests for user account and session management endpoints."""

import pytest


@pytest.mark.asyncio
async def test_account_profile_read_and_update(client):
    """Test reading and updating user profile details."""
    reg = await client.post(
        "/api/auth/register",
        json={"email": "profile_test@veylor.dev", "password": "Password123!", "name": "Initial Name"},
    )
    cookie = reg.cookies["veylor_session"]

    # 1. Read profile
    get_resp = await client.get("/api/account", cookies={"veylor_session": cookie})
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Initial Name"
    assert get_resp.json()["email"] == "profile_test@veylor.dev"

    # 2. Update profile
    patch_resp = await client.patch(
        "/api/account",
        json={"name": "Updated Name", "given_name": "Updated", "family_name": "Name"},
        cookies={"veylor_session": cookie},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["user"]["name"] == "Updated Name"

    # 3. Verify changes persisted
    verify_resp = await client.get("/api/account", cookies={"veylor_session": cookie})
    assert verify_resp.json()["name"] == "Updated Name"


@pytest.mark.asyncio
async def test_account_list_and_revoke_sessions(client):
    """Test listing active browser sessions and revoking a specific session."""
    reg = await client.post(
        "/api/auth/register",
        json={"email": "sessions_test@veylor.dev", "password": "Password123!", "name": "Sessions User"},
    )
    cookie = reg.cookies["veylor_session"]

    # 1. List active sessions
    sessions_resp = await client.get("/api/account/sessions", cookies={"veylor_session": cookie})
    assert sessions_resp.status_code == 200
    sessions = sessions_resp.json()
    assert len(sessions) == 1
    session_id = sessions[0]["id"]

    # 2. Revoke the session
    del_resp = await client.delete(
        f"/api/account/sessions/{session_id}",
        cookies={"veylor_session": cookie},
    )
    assert del_resp.status_code == 200

    # 3. Accessing /api/account should now be unauthorized
    unauth_resp = await client.get("/api/account", cookies={"veylor_session": cookie})
    assert unauth_resp.status_code == 401
