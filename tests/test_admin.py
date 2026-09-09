"""Tests for Admin OAuth client management API."""

import pytest


@pytest.mark.asyncio
async def test_admin_api_requires_valid_key(client):
    """Test that admin endpoints strictly reject requests without valid X-Admin-API-Key."""
    # 1. No key -> 403
    r1 = await client.get("/api/admin/clients")
    assert r1.status_code == 403

    # 2. Invalid key -> 403
    r2 = await client.get("/api/admin/clients", headers={"X-Admin-API-Key": "wrong_key"})
    assert r2.status_code == 403

    # 3. Valid key -> 200
    r3 = await client.get("/api/admin/clients", headers={"X-Admin-API-Key": "test_admin_secret_key"})
    assert r3.status_code == 200


@pytest.mark.asyncio
async def test_admin_client_crud_operations(client):
    """Test creating, reading, and updating an OAuth client via admin API."""
    headers = {"X-Admin-API-Key": "test_admin_secret_key"}

    # 1. Create client
    new_client = {
        "client_id": "test_app",
        "client_name": "Test Application",
        "client_type": "public",
        "redirect_uris": ["http://localhost:4000/callback"],
        "allowed_scopes": ["openid", "profile"],
        "trusted": False,
    }
    create_resp = await client.post("/api/admin/clients", json=new_client, headers=headers)
    assert create_resp.status_code == 201
    assert create_resp.json()["client_id"] == "test_app"

    # 2. Get client by id
    get_resp = await client.get("/api/admin/clients/test_app", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["client_name"] == "Test Application"

    # 3. Update client
    patch_resp = await client.patch(
        "/api/admin/clients/test_app",
        json={"client_name": "Updated Test App", "trusted": True},
        headers=headers,
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["client_name"] == "Updated Test App"
    assert patch_resp.json()["trusted"] is True
