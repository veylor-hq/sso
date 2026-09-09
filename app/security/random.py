"""Cryptographic randomness and token hashing utilities."""

import hashlib
import hmac
import secrets
import time


def generate_opaque_id(prefix: str = "usr") -> str:
    """Generate an opaque immutable ID with a prefix, timestamp, and randomness.

    Matches the user ID requirement: usr_01JXXXXXXXXXXXX.
    Uses Crockford Base32-like encoding based on millisecond timestamp + random bytes.
    """
    # Crockford base32 alphabet
    ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    # 48-bit millisecond timestamp (similar to ULID)
    timestamp_ms = int(time.time() * 1000)
    time_chars = []
    for _ in range(10):
        time_chars.append(ENCODING[timestamp_ms & 0x1F])
        timestamp_ms >>= 5
    time_part = "".join(reversed(time_chars))

    # 80-bit cryptographic randomness (16 chars)
    rand_chars = "".join(secrets.choice(ENCODING) for _ in range(16))

    return f"{prefix}_{time_part}{rand_chars}"


def generate_opaque_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure URL-safe opaque string."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Compute SHA-256 hex digest of a token before storing in MongoDB."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time to mitigate timing attacks."""
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))
