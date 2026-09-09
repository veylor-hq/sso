"""Tests for Admin Command & Insights Portal."""

import pytest
from app.models.oauth_client import OAuthClient
from app.models.user import User


@pytest.mark.asyncio
async def test_admin_portal_unauthorized_access(client):
    """Ensure unauthenticated or unauthorized requests are rejected."""
    # 1. API endpoint without credentials
    resp = await client.get("/api/admin/insights")
    assert resp.status_code == 403

    # 2. Web UI endpoint redirects to /admin/login
    web_resp = await client.get("/admin/insights", follow_redirects=False)
    assert web_resp.status_code == 302
    assert "/admin/login" in web_resp.headers["location"]


@pytest.mark.asyncio
async def test_admin_portal_insights(client):
    """Test insights aggregation metrics."""
    headers = {"X-Admin-API-Key": "test_admin_secret_key"}

    # Seed test users with app assignments
    u1 = User(
        id="usr_test_insight_1",
        email="user1@veylor.dev",
        name="User One",
        password_hash="$argon2id$mockhash",
        email_verified=True,
        authorized_apps=["egarage"],
    )
    u2 = User(
        id="usr_test_insight_2",
        email="user2@veylor.dev",
        name="User Two",
        password_hash="$argon2id$mockhash",
        email_verified=False,
        authorized_apps=["egarage", "relay"],
    )
    await u1.insert()
    await u2.insert()

    resp = await client.get("/api/admin/insights", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "summary" in data
    assert data["summary"]["total_users"] >= 2
    assert "apps_distribution" in data
    assert data["apps_distribution"]["egarage"] >= 2
    assert data["apps_distribution"]["relay"] >= 1
    assert "providers" in data


@pytest.mark.asyncio
async def test_admin_clients_crud_and_secret_regeneration(client):
    """Test OAuth client registration, updates, and secret regeneration."""
    headers = {"X-Admin-API-Key": "test_admin_secret_key"}

    # 1. Create client with auto-generated secret
    new_client = {
        "client_id": "portal_test_app",
        "client_name": "Portal Test Application",
        "client_type": "confidential",
        "redirect_uris": ["https://app.veylor.dev/callback"],
        "allowed_scopes": ["openid", "profile", "email"],
        "trusted": True,
        "generate_secret": True,
    }
    create_resp = await client.post("/api/admin/clients", json=new_client, headers=headers)
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["client_id"] == "portal_test_app"
    assert created_data["trusted"] is True
    assert created_data["client_secret"].startswith("vsec_")

    # 2. Regenerate secret
    regen_resp = await client.post("/api/admin/clients/portal_test_app/regenerate-secret", headers=headers)
    assert regen_resp.status_code == 200
    regen_data = regen_resp.json()
    assert regen_data["client_secret"].startswith("vsec_")
    assert regen_data["client_secret"] != created_data["client_secret"]

    # 3. Update client
    update_resp = await client.put(
        "/api/admin/clients/portal_test_app",
        json={"client_name": "Renamed Application", "disabled": True},
        headers=headers,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["client_name"] == "Renamed Application"
    assert update_resp.json()["disabled"] is True

    # 4. Delete client
    del_resp = await client.delete("/api/admin/clients/portal_test_app", headers=headers)
    assert del_resp.status_code == 200

    # Verify deleted
    get_resp = await client.get("/api/admin/clients/portal_test_app", headers=headers)
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_users_directory_filtering_and_crud(client):
    """Test user directory search, app filtering, editing, and password reset."""
    headers = {"X-Admin-API-Key": "test_admin_secret_key"}

    # 1. Create user via admin API
    user_payload = {
        "email": "directory_test@veylor.dev",
        "name": "Directory Test",
        "password": "SecurePassword999!",
        "email_verified": True,
        "authorized_apps": ["relay", "warden"],
        "is_admin": False,
    }
    create_resp = await client.post("/api/admin/users", json=user_payload, headers=headers)
    assert create_resp.status_code == 201
    user_data = create_resp.json()
    user_id = user_data["id"]
    assert user_data["email"] == "directory_test@veylor.dev"
    assert "relay" in user_data["authorized_apps"]

    # 2. Filter users by app: relay
    filter_relay = await client.get("/api/admin/users?app=relay", headers=headers)
    assert filter_relay.status_code == 200
    relay_items = filter_relay.json()["items"]
    assert any(u["id"] == user_id for u in relay_items)

    # 3. Filter users by app: pager (should not include this user)
    filter_pager = await client.get("/api/admin/users?app=pager", headers=headers)
    assert filter_pager.status_code == 200
    pager_items = filter_pager.json()["items"]
    assert not any(u["id"] == user_id for u in pager_items)

    # 4. Search by email query
    search_resp = await client.get("/api/admin/users?search=directory_test", headers=headers)
    assert search_resp.status_code == 200
    assert len(search_resp.json()["items"]) >= 1

    # 5. Update user
    update_resp = await client.put(
        f"/api/admin/users/{user_id}",
        json={"name": "Directory Test Updated", "disabled": True, "authorized_apps": ["egarage", "relay"]},
        headers=headers,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "Directory Test Updated"
    assert update_resp.json()["disabled"] is True
    assert "egarage" in update_resp.json()["authorized_apps"]

    # 6. Directly reset password
    reset_resp = await client.post(
        f"/api/admin/users/{user_id}/reset-password",
        json={"new_password": "NewSecretPassword123!"},
        headers=headers,
    )
    assert reset_resp.status_code == 200

    # 7. Delete user
    del_resp = await client.delete(f"/api/admin/users/{user_id}", headers=headers)
    assert del_resp.status_code == 200

    # Verify deleted
    get_resp = await client.get(f"/api/admin/users/{user_id}", headers=headers)
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_web_portal_pages(client):
    """Test server-rendered web admin pages with admin key cookie."""
    cookies = {"veylor_admin_key": "test_admin_secret_key"}

    # Insights page
    insights_resp = await client.get("/admin/insights", cookies=cookies)
    assert insights_resp.status_code == 200
    assert "Veylor SSO // Admin Portal" in insights_resp.text
    assert "Insights &amp; Overview" in insights_resp.text or "Insights" in insights_resp.text

    # Clients page
    clients_resp = await client.get("/admin/clients", cookies=cookies)
    assert clients_resp.status_code == 200
    assert "Trusted Websites &amp; OAuth Clients" in clients_resp.text or "Trusted Websites" in clients_resp.text

    # Users page
    users_resp = await client.get("/admin/users", cookies=cookies)
    assert users_resp.status_code == 200
    assert "Global User Directory" in users_resp.text
    assert "Filter By App" in users_resp.text

    # Sessions page
    sessions_resp = await client.get("/admin/sessions", cookies=cookies)
    assert sessions_resp.status_code == 200
    assert "Active Browser Sessions" in sessions_resp.text
