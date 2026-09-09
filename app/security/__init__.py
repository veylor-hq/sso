"""Security utilities for Veylor SSO."""

from app.security.passwords import hash_password, verify_password, validate_password_complexity
from app.security.pkce import generate_code_verifier, compute_code_challenge, verify_pkce
from app.security.random import generate_opaque_id, generate_opaque_token, hash_token, constant_time_compare
from app.security.jwt import get_key_manager, create_id_token, create_access_token, decode_and_verify_token
from app.security.csrf import generate_csrf_token, verify_csrf_token
from app.security.rate_limit import check_rate_limit, get_client_ip

__all__ = [
    "hash_password",
    "verify_password",
    "validate_password_complexity",
    "generate_code_verifier",
    "compute_code_challenge",
    "verify_pkce",
    "generate_opaque_id",
    "generate_opaque_token",
    "hash_token",
    "constant_time_compare",
    "get_key_manager",
    "create_id_token",
    "create_access_token",
    "decode_and_verify_token",
    "generate_csrf_token",
    "verify_csrf_token",
    "check_rate_limit",
    "get_client_ip",
]
