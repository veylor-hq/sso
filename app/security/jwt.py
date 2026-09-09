"""JSON Web Token (JWT), JWKS, and RSA key management."""

import base64
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.exceptions import PyJWTError

from app.config import get_settings


class KeyManager:
    """Manages RSA asymmetric signing keys and JWKS generation."""

    def __init__(self):
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._public_key: Optional[rsa.RSAPublicKey] = None
        self._kid: str = get_settings().SIGNING_KEY_ID

    def get_kid(self) -> str:
        return self._kid

    def load_or_generate_keys(self) -> None:
        """Load private RSA key from file or generate a fresh key pair."""
        settings = get_settings()
        key_path = Path(settings.SIGNING_KEY_PATH)

        if key_path.exists():
            with open(key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )
        else:
            # Generate 2048-bit RSA key
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Ensure parent dir exists and save
            key_path.parent.mkdir(parents=True, exist_ok=True)
            pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, "wb") as f:
                f.write(pem)

        self._public_key = self._private_key.public_key()

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        if self._private_key is None:
            self.load_or_generate_keys()
        return self._private_key

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        if self._public_key is None:
            self.load_or_generate_keys()
        return self._public_key

    def get_public_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def get_jwk(self) -> Dict[str, Any]:
        """Convert public RSA key to JSON Web Key (JWK) format."""
        numbers = self.public_key.public_numbers()
        # Helper to base64url encode big integers
        def int_to_b64url(val: int) -> str:
            byte_len = (val.bit_length() + 7) // 8
            byte_val = val.to_bytes(byte_len, byteorder="big")
            return base64.urlsafe_b64encode(byte_val).decode("ascii").rstrip("=")

        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self._kid,
            "n": int_to_b64url(numbers.n),
            "e": int_to_b64url(numbers.e),
        }

    def get_jwks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return JWKS dictionary for /.well-known/jwks.json."""
        return {"keys": [self.get_jwk()]}


_key_manager = KeyManager()


def get_key_manager() -> KeyManager:
    return _key_manager


def create_id_token(
    sub: str,
    aud: str,
    claims: Optional[Dict[str, Any]] = None,
    nonce: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> str:
    """Generate a signed OpenID Connect ID Token (RS256)."""
    settings = get_settings()
    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + (ttl_seconds or settings.ID_TOKEN_TTL_SECONDS)

    payload: Dict[str, Any] = {
        "iss": settings.SSO_ISSUER,
        "sub": sub,
        "aud": aud,
        "iat": now,
        "exp": exp,
    }

    if nonce:
        payload["nonce"] = nonce

    if claims:
        for k, v in claims.items():
            if v is not None and k not in payload:
                payload[k] = v

    km = get_key_manager()
    headers = {
        "kid": km.get_kid(),
        "alg": "RS256",
        "typ": "JWT",
    }

    return jwt.encode(
        payload=payload,
        key=km.private_key,
        algorithm="RS256",
        headers=headers,
    )


def create_access_token(
    sub: str,
    client_id: str,
    scopes: List[str],
    aud: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> str:
    """Generate an OAuth 2.0 signed Bearer access token."""
    settings = get_settings()
    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + (ttl_seconds or settings.ACCESS_TOKEN_TTL_SECONDS)

    payload: Dict[str, Any] = {
        "iss": settings.SSO_ISSUER,
        "sub": sub,
        "client_id": client_id,
        "aud": aud or client_id,
        "scope": " ".join(scopes),
        "iat": now,
        "exp": exp,
        "jti": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
    }

    km = get_key_manager()
    headers = {
        "kid": km.get_kid(),
        "alg": "RS256",
        "typ": "at+jwt",
    }

    return jwt.encode(
        payload=payload,
        key=km.private_key,
        algorithm="RS256",
        headers=headers,
    )


def decode_and_verify_token(
    token: str,
    expected_aud: Optional[str] = None,
    expected_issuer: Optional[str] = None,
    expected_typ: Optional[str] = None,
) -> Dict[str, Any]:
    """Decode and verify an RSA-signed token using the active public key.
    
    If expected_typ is specified (e.g. 'at+jwt'), enforces that the token's typ header matches.
    """
    settings = get_settings()
    issuer = expected_issuer or settings.SSO_ISSUER
    km = get_key_manager()

    if expected_typ:
        try:
            unverified_header = jwt.get_unverified_header(token)
            actual_typ = unverified_header.get("typ", "")
            if actual_typ.lower() != expected_typ.lower():
                raise PyJWTError(f"Invalid token type: expected '{expected_typ}', got '{actual_typ}'")
        except PyJWTError:
            raise
        except Exception as e:
            raise PyJWTError(f"Failed to inspect token header: {str(e)}")

    options = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_iat": True,
        "verify_iss": True,
        "verify_aud": expected_aud is not None,
    }

    return jwt.decode(
        jwt=token,
        key=km.public_key,
        algorithms=["RS256"],
        issuer=issuer,
        audience=expected_aud,
        options=options,
    )
