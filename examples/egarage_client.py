"""eGarage Veylor SSO Integration Example.

This script demonstrates how an application within the Veylor ecosystem (such as eGarage)
implements Single Sign-On using OAuth 2.0 and OpenID Connect with Authorization Code Flow & PKCE (S256).

Workflow:
1. Generate cryptographically random state & nonce.
2. Generate PKCE code_verifier and compute S256 code_challenge.
3. Redirect user to Veylor SSO /authorize.
4. Receive authorization code callback, verify state.
5. Exchange code + code_verifier at /token.
6. Retrieve public keys from /.well-known/jwks.json.
7. Cryptographically verify the ID token signature, issuer, audience, exp, and nonce.
8. Extract immutable Veylor sub (usr_01J...).
9. Link local eGarage user (local_user.veylor_user_id = sub) and create eGarage session.
"""

import base64
import hashlib
import json
import re
import secrets
import urllib.parse
from typing import Any, Dict, Optional
import httpx
import jwt
from jwt import PyJWKClient


class EGarageOIDCClient:
    def __init__(
        self,
        sso_issuer: str = "http://localhost:8000",
        client_id: str = "egarage",
        redirect_uri: str = "http://localhost:3000/auth/callback",
    ):
        self.sso_issuer = sso_issuer.rstrip("/")
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.jwks_url = f"{self.sso_issuer}/.well-known/jwks.json"
        self.jwks_client = PyJWKClient(self.jwks_url)

    # 1. PKCE Helpers
    @staticmethod
    def generate_pkce_verifier() -> str:
        """Generate a random 64-character PKCE code_verifier."""
        token = secrets.token_urlsafe(64)
        cleaned = re.sub(r"[^A-Za-z0-9\-._~]", "", token)
        return cleaned[:64]

    @staticmethod
    def compute_s256_challenge(verifier: str) -> str:
        """Compute BASE64URL(SHA256(verifier)) without padding."""
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    # 2. Build Authorization URL
    def create_authorization_request(
        self,
        scope: str = "openid profile email",
    ) -> Dict[str, str]:
        """Prepare parameters and URL for redirecting the user to Veylor SSO."""
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = self.generate_pkce_verifier()
        challenge = self.compute_s256_challenge(verifier)

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{self.sso_issuer}/authorize?{urllib.parse.urlencode(params)}"

        return {
            "auth_url": auth_url,
            "state": state,
            "nonce": nonce,
            "code_verifier": verifier,
        }

    # 3. Exchange Code at /token
    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
    ) -> Dict[str, Any]:
        """Exchange the authorization code for tokens at the token endpoint."""
        token_endpoint = f"{self.sso_issuer}/token"
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.client_id,
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "code_verifier": code_verifier,
                },
            )
            if response.status_code != 200:
                raise RuntimeError(f"Token exchange failed: {response.text}")
            return response.json()

    # 4. Validate ID Token using JWKS
    def validate_id_token(
        self,
        id_token_jwt: str,
        expected_nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify the ID token's RS256 signature using JWKS, issuer, audience, and nonce."""
        signing_key = self.jwks_client.get_signing_key_from_jwt(id_token_jwt)

        claims = jwt.decode(
            jwt=id_token_jwt,
            key=signing_key.key,
            algorithms=["RS256"],
            issuer=self.sso_issuer,
            audience=self.client_id,
            options={"verify_exp": True, "verify_iss": True, "verify_aud": True},
        )

        # Nonce verification
        if expected_nonce:
            token_nonce = claims.get("nonce")
            if not token_nonce or not secrets.compare_digest(token_nonce, expected_nonce):
                raise ValueError("ID Token nonce mismatch! Possible replay attack.")

        return claims

    # 5. Fetch UserInfo
    async def get_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetch user profile from /userinfo endpoint using Bearer access token."""
        userinfo_endpoint = f"{self.sso_issuer}/userinfo"
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code != 200:
                raise RuntimeError(f"UserInfo request failed: {resp.text}")
            return resp.json()


# ==============================================================================
# Simulated Local eGarage Database & Session Storage
# ==============================================================================
class MockEGarageDatabase:
    def __init__(self):
        self.users = {}  # local_user_id -> UserRecord
        self.veylor_mapping = {}  # veylor_user_id (sub) -> local_user_id

    def find_or_create_local_user(self, veylor_sub: str, email: str, name: str):
        if veylor_sub in self.veylor_mapping:
            user_id = self.veylor_mapping[veylor_sub]
            return self.users[user_id], False

        local_id = f"local_gar_{len(self.users) + 1}"
        user_record = {
            "id": local_id,
            "veylor_user_id": veylor_sub,  # Linking key
            "email": email,
            "name": name,
            "role": "mechanic",
        }
        self.users[local_id] = user_record
        self.veylor_mapping[veylor_sub] = local_id
        return user_record, True


if __name__ == "__main__":
    import asyncio

    async def main():
        print("=" * 60)
        print("eGarage OpenID Connect Integration Demo")
        print("=" * 60)

        client = EGarageOIDCClient()
        db = MockEGarageDatabase()

        # Step 1: Client prepares login flow
        auth_req = client.create_authorization_request()
        print("\n1. Generated PKCE verifier & challenge")
        print(f"   code_verifier: {auth_req['code_verifier']}")
        print(f"   state:         {auth_req['state']}")
        print(f"   nonce:         {auth_req['nonce']}")
        print(f"\n2. Generated SSO Redirect URL:")
        print(f"   {auth_req['auth_url']}")

        print("\n3. When the user visits this URL:")
        print("   - If already signed in to Veylor SSO, SSO issues the authorization code immediately (0 clicks!).")
        print("   - If not signed in, Veylor prompts for password once, then returns code.")

        print("\n4. Application receives callback at /auth/callback?code=...&state=...")
        print("   - Verifies state matches the stored session state.")
        print("   - Exchanging code via POST /token with PKCE verifier.")
        print("   - Verifies ID Token using public keys from /.well-known/jwks.json.")
        print("   - Extracts immutable sub (usr_01J...) to map to local eGarage account:")
        print("     `local_user.veylor_user_id = id_token['sub']`")

    asyncio.run(main())
