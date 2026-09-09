"""Tests for OAuth 2.0 Authorization Code Flow & PKCE."""

import urllib.parse
from datetime import datetime, timedelta, timezone
import pytest
from app.models.authorization_code import AuthorizationCode
from app.models.oauth_client import OAuthClient
from app.security.pkce import compute_code_challenge, generate_code_verifier


@pytest.mark.asyncio
async def test_unknown_client_rejected(client):
    """Test that authorization request with unknown client_id is rejected."""
    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier)

    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "nonexistent_app",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code in (400, 401)
    assert "unauthorized_client" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_disabled_client_rejected(client):
    """Test that disabled clients are rejected."""
    oc = await OAuthClient.find_one(OAuthClient.client_id == "egarage")
    oc.disabled = True
    await oc.save()

    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier)

    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code in (400, 401)
    assert "unauthorized_client" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_invalid_redirect_uri_rejected(client):
    """Test that unregistered redirect_uri is strictly rejected (no wildcard or loose matching)."""
    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier)

    # Attempt open redirect or malicious domain
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "https://malicious-attacker.com/steal_code",
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 400
    assert "redirect_uri" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_invalid_scope_rejected(client):
    """Test that requesting unallowed scopes is rejected."""
    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier)

    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid admin:all_access_root",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 400
    assert "invalid_scope" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_missing_pkce_and_wrong_method_rejected(client):
    """Test that missing PKCE or using 'plain' method is rejected."""
    # 1. Missing PKCE
    r1 = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid",
        },
    )
    assert r1.status_code == 400
    assert "code_challenge is required" in r1.json()["detail"]

    # 2. Insecure method 'plain'
    verifier = generate_code_verifier()
    r2 = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid",
            "code_challenge": verifier,
            "code_challenge_method": "plain",
        },
    )
    assert r2.status_code == 400
    assert "s256" in r2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_full_successful_oauth_pkce_flow(client):
    """Test full authorization code flow with PKCE from /authorize to /token exchange."""
    # 1. Register and sign in user to establish SSO browser session
    reg = await client.post(
        "/api/auth/register",
        json={"email": "sso_user@egarage.uk", "password": "Password123!", "name": "Veylor User"},
    )
    session_cookie = reg.cookies["veylor_session"]

    # 2. Prepare PKCE
    code_verifier = generate_code_verifier()
    code_challenge = compute_code_challenge(code_verifier)
    state = "state_xyz_123"
    nonce = "nonce_abc_456"

    # 3. Hit /authorize with active SSO cookie
    # eGarage is a trusted first-party client, so it should redirect directly to callback!
    auth_resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies={"veylor_session": session_cookie},
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    redirect_location = auth_resp.headers["location"]
    assert redirect_location.startswith("http://localhost:3000/auth/callback?")

    parsed = urllib.parse.urlparse(redirect_location)
    qs = urllib.parse.parse_qs(parsed.query)
    assert "code" in qs
    assert qs["state"][0] == state
    auth_code = qs["code"][0]

    # 4. Exchange code at /token with PKCE verifier
    token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "egarage",
            "code": auth_code,
            "redirect_uri": "http://localhost:3000/auth/callback",
            "code_verifier": code_verifier,
        },
    )
    assert token_resp.status_code == 200
    token_data = token_resp.json()

    assert "access_token" in token_data
    assert "id_token" in token_data
    assert token_data["token_type"] == "Bearer"
    assert token_data["expires_in"] > 0
    assert "openid" in token_data["scope"]


@pytest.mark.asyncio
async def test_authorization_code_single_use_and_replay_prevention(client):
    """Test that authorization code cannot be used twice (replay prevention)."""
    # 1. Setup session and issue code
    reg = await client.post(
        "/api/auth/register",
        json={"email": "replay_user@egarage.uk", "password": "Password123!", "name": "Replay User"},
    )
    session_cookie = reg.cookies["veylor_session"]

    code_verifier = generate_code_verifier()
    code_challenge = compute_code_challenge(code_verifier)

    auth_resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies={"veylor_session": session_cookie},
        follow_redirects=False,
    )
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    auth_code = urllib.parse.parse_qs(parsed.query)["code"][0]

    # First exchange succeeds
    t1 = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "egarage",
            "code": auth_code,
            "redirect_uri": "http://localhost:3000/auth/callback",
            "code_verifier": code_verifier,
        },
    )
    assert t1.status_code == 200

    # Second exchange with the same code MUST fail with invalid_grant
    t2 = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "egarage",
            "code": auth_code,
            "redirect_uri": "http://localhost:3000/auth/callback",
            "code_verifier": code_verifier,
        },
    )
    assert t2.status_code == 400
    assert t2.json()["error"] == "invalid_grant"
    assert "replay" in t2.json()["error_description"].lower()


@pytest.mark.asyncio
async def test_wrong_client_and_wrong_redirect_uri_exchange(client):
    """Test that exchanging code with mismatched client or redirect_uri fails."""
    reg = await client.post(
        "/api/auth/register",
        json={"email": "mismatch@egarage.uk", "password": "Password123!", "name": "Mismatch"},
    )
    session_cookie = reg.cookies["veylor_session"]

    code_verifier = generate_code_verifier()
    code_challenge = compute_code_challenge(code_verifier)

    auth_resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies={"veylor_session": session_cookie},
        follow_redirects=False,
    )
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    auth_code = urllib.parse.parse_qs(parsed.query)["code"][0]

    # 1. Wrong client attempting to exchange
    wrong_client_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "relay",  # issued to egarage, attempted by relay!
            "code": auth_code,
            "redirect_uri": "http://localhost:3000/auth/callback",
            "code_verifier": code_verifier,
        },
    )
    assert wrong_client_resp.status_code == 400
    assert wrong_client_resp.json()["error"] == "invalid_grant"

    # 2. Wrong redirect_uri attempting to exchange
    wrong_uri_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "egarage",
            "code": auth_code,
            "redirect_uri": "https://egarageapp.uk/auth/callback",  # issued for localhost
            "code_verifier": code_verifier,
        },
    )
    assert wrong_uri_resp.status_code == 400
    assert wrong_uri_resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_incorrect_code_verifier_rejected(client):
    """Test that providing an incorrect PKCE code_verifier fails exchange."""
    reg = await client.post(
        "/api/auth/register",
        json={"email": "pkce_fail@veylor.dev", "password": "Password123!", "name": "PKCE Fail"},
    )
    session_cookie = reg.cookies["veylor_session"]

    code_verifier = generate_code_verifier()
    code_challenge = compute_code_challenge(code_verifier)

    auth_resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies={"veylor_session": session_cookie},
        follow_redirects=False,
    )
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    auth_code = urllib.parse.parse_qs(parsed.query)["code"][0]

    # Submit totally wrong code_verifier
    wrong_verifier = generate_code_verifier()
    token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "egarage",
            "code": auth_code,
            "redirect_uri": "http://localhost:3000/auth/callback",
            "code_verifier": wrong_verifier,
        },
    )
    assert token_resp.status_code == 400
    assert token_resp.json()["error"] == "invalid_grant"
    assert "code_verifier" in token_resp.json()["error_description"].lower()
