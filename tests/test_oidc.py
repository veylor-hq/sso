"""Tests for OpenID Connect Discovery, JWKS, ID Tokens, and UserInfo."""

import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from app.config import get_settings
from app.security.jwt import get_key_manager, create_id_token
from app.security.pkce import compute_code_challenge, generate_code_verifier


@pytest.mark.asyncio
async def test_oidc_discovery_endpoint(client):
    """Test standard compliance of /.well-known/openid-configuration."""
    resp = await client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()

    settings = get_settings()
    issuer = settings.SSO_ISSUER.rstrip("/")
    assert data["issuer"] == issuer
    assert data["authorization_endpoint"] == f"{issuer}/authorize"
    assert data["token_endpoint"] == f"{issuer}/token"
    assert data["userinfo_endpoint"] == f"{issuer}/userinfo"
    assert data["jwks_uri"] == f"{issuer}/.well-known/jwks.json"
    assert "code" in data["response_types_supported"]
    assert "authorization_code" in data["grant_types_supported"]
    assert "S256" in data["code_challenge_methods_supported"]
    assert "RS256" in data["id_token_signing_alg_values_supported"]
    assert "openid" in data["scopes_supported"]
    assert "sub" in data["claims_supported"]


@pytest.mark.asyncio
async def test_jwks_endpoint_structure(client):
    """Test that /.well-known/jwks.json returns a valid JWK set."""
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()

    assert "keys" in data
    assert len(data["keys"]) >= 1
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


@pytest.mark.asyncio
async def test_id_token_validation_positive_and_negative(client):
    """Test cryptographic verification of ID tokens including signature, issuer, audience, and nonce."""
    km = get_key_manager()
    settings = get_settings()
    public_pem = km.get_public_pem()

    sub = "usr_01JTESTUSER123456789"
    aud = "egarage"
    nonce = "test_nonce_value_123"

    # 1. Valid ID Token
    valid_jwt = create_id_token(
        sub=sub,
        aud=aud,
        claims={"email": "mechanic@egarage.uk", "name": "Mechanic Bob"},
        nonce=nonce,
        ttl_seconds=3600,
    )

    decoded = jwt.decode(
        jwt=valid_jwt,
        key=km.public_key,
        algorithms=["RS256"],
        issuer=settings.SSO_ISSUER,
        audience=aud,
    )
    assert decoded["sub"] == sub
    assert decoded["aud"] == aud
    assert decoded["email"] == "mechanic@egarage.uk"
    assert decoded["nonce"] == nonce

    # 2. Invalid Signature (signed by a completely different private RSA key)
    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_jwt = jwt.encode(
        payload={"sub": sub, "iss": settings.SSO_ISSUER, "aud": aud, "exp": int(time.time()) + 3600},
        key=foreign_key,
        algorithm="RS256",
    )
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            jwt=forged_jwt,
            key=km.public_key,
            algorithms=["RS256"],
            issuer=settings.SSO_ISSUER,
            audience=aud,
        )

    # 3. Incorrect Issuer
    with pytest.raises(jwt.InvalidIssuerError):
        jwt.decode(
            jwt=valid_jwt,
            key=km.public_key,
            algorithms=["RS256"],
            issuer="https://evil-spoofed-issuer.com",
            audience=aud,
        )

    # 4. Incorrect Audience
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            jwt=valid_jwt,
            key=km.public_key,
            algorithms=["RS256"],
            issuer=settings.SSO_ISSUER,
            audience="warden",  # expected egarage
        )

    # 5. Expired Token
    expired_jwt = create_id_token(
        sub=sub,
        aud=aud,
        ttl_seconds=-10,  # expired 10 seconds ago
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            jwt=expired_jwt,
            key=km.public_key,
            algorithms=["RS256"],
            issuer=settings.SSO_ISSUER,
            audience=aud,
        )


@pytest.mark.asyncio
async def test_userinfo_endpoint_with_bearer_token(client):
    """Test that /userinfo validates Bearer access tokens and returns matching sub."""
    # 1. Register user
    reg = await client.post(
        "/api/auth/register",
        json={"email": "userinfo_test@egarage.uk", "password": "Password123!", "name": "UserInfo User"},
    )
    user_id = reg.json()["id"]
    session_cookie = reg.cookies["veylor_session"]

    # 2. Get tokens via OAuth flow
    code_verifier = generate_code_verifier()
    challenge = compute_code_challenge(code_verifier)

    auth_resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "egarage",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scope": "openid profile email",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        cookies={"veylor_session": session_cookie},
        follow_redirects=False,
    )
    import urllib.parse
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    code = urllib.parse.parse_qs(parsed.query)["code"][0]

    token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "egarage",
            "code": code,
            "redirect_uri": "http://localhost:3000/auth/callback",
            "code_verifier": code_verifier,
        },
    )
    tokens = token_resp.json()
    access_token = tokens["access_token"]
    id_token = tokens["id_token"]

    # Decode ID token to get ID token sub
    km = get_key_manager()
    decoded_id = jwt.decode(id_token, key=km.public_key, algorithms=["RS256"], options={"verify_aud": False})
    id_token_sub = decoded_id["sub"]

    # 3. Request /userinfo without token -> 401
    unauth = await client.get("/userinfo")
    assert unauth.status_code == 401

    # 4. Request /userinfo with invalid token -> 401
    bad_token = await client.get("/userinfo", headers={"Authorization": "Bearer invalid.random.token"})
    assert bad_token.status_code == 401

    # 5. Request /userinfo with valid access token -> 200
    userinfo_resp = await client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert userinfo_resp.status_code == 200
    uinfo = userinfo_resp.json()

    # The UserInfo sub MUST match the ID token sub!
    assert uinfo["sub"] == user_id
    assert uinfo["sub"] == id_token_sub
    assert uinfo["email"] == "userinfo_test@egarage.uk"
    assert uinfo["name"] == "UserInfo User"


@pytest.mark.asyncio
async def test_egarage_client_library_flow(client):
    """Test the eGarage integration helper and local user mapping."""
    from examples.egarage_client import EGarageOIDCClient, MockEGarageDatabase

    # 1. Register user in SSO
    reg = await client.post(
        "/api/auth/register",
        json={"email": "mechanic_dan@egarage.uk", "password": "Password123!", "name": "Dan Mechanic"},
    )
    user_id = reg.json()["id"]
    session_cookie = reg.cookies["veylor_session"]

    # 2. Client initiates flow
    eg_client = EGarageOIDCClient(sso_issuer="http://testserver")
    db = MockEGarageDatabase()
    auth_req = eg_client.create_authorization_request()

    # 3. Simulate browser hitting /authorize
    auth_resp = await client.get(
        auth_req["auth_url"].replace("http://testserver", ""),
        cookies={"veylor_session": session_cookie},
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    import urllib.parse
    cb_parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    cb_qs = urllib.parse.parse_qs(cb_parsed.query)

    # 4. Client verifies state
    assert cb_qs["state"][0] == auth_req["state"]
    code = cb_qs["code"][0]

    # 5. Client exchanges code at /token
    token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": eg_client.client_id,
            "code": code,
            "redirect_uri": eg_client.redirect_uri,
            "code_verifier": auth_req["code_verifier"],
        },
    )
    assert token_resp.status_code == 200
    token_data = token_resp.json()

    # 6. Validate ID Token using JWKS public keys
    jwks_resp = await client.get("/.well-known/jwks.json")
    jwks_data = jwks_resp.json()
    from jwt.algorithms import RSAAlgorithm
    key_dict = jwks_data["keys"][0]
    public_key = RSAAlgorithm.from_jwk(key_dict)

    decoded = jwt.decode(
        jwt=token_data["id_token"],
        key=public_key,
        algorithms=["RS256"],
        issuer="http://testserver",
        audience="egarage",
    )
    assert decoded["sub"] == user_id
    assert decoded["nonce"] == auth_req["nonce"]

    # 7. Map to local eGarage account using sub
    local_user, is_new = db.find_or_create_local_user(
        veylor_sub=decoded["sub"],
        email=decoded["email"],
        name=decoded["name"],
    )
    assert is_new is True
    assert local_user["veylor_user_id"] == user_id

    # Second login with same Veylor account retrieves same local account
    local_user2, is_new2 = db.find_or_create_local_user(
        veylor_sub=decoded["sub"],
        email=decoded["email"],
        name=decoded["name"],
    )
    assert is_new2 is False
    assert local_user2["id"] == local_user["id"]
