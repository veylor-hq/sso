"""Rate limiter supporting Redis with transparent in-memory fallback."""

import time
from typing import Dict, List, Optional
import redis.asyncio as aioredis
from fastapi import Request, HTTPException, status
from app.config import get_settings

_redis_client: Optional[aioredis.Redis] = None
_in_memory_buckets: Dict[str, List[float]] = {}


async def get_redis_client() -> Optional[aioredis.Redis]:
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        if settings.REDIS_URL:
            try:
                client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
                await client.ping()
                _redis_client = client
            except Exception:
                _redis_client = None
    return _redis_client


async def check_rate_limit(
    key: str,
    max_requests: int,
    window_seconds: int = 60,
) -> bool:
    """Sliding-window / fixed-window rate limiter. Returns True if allowed, False if exceeded."""
    r = await get_redis_client()
    now = time.time()

    if r is not None:
        try:
            redis_key = f"rl:{key}"
            pipe = r.pipeline()
            # Remove old timestamps
            pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
            # Add current timestamp
            pipe.zadd(redis_key, {str(now): now})
            # Count elements in window
            pipe.zcard(redis_key)
            # Set TTL
            pipe.expire(redis_key, window_seconds + 5)
            results = await pipe.execute()
            count = results[2]
            return count <= max_requests
        except Exception:
            # Fall back to in-memory if Redis fails
            pass

    # In-memory sliding window fallback
    timestamps = _in_memory_buckets.get(key, [])
    cutoff = now - window_seconds
    timestamps = [t for t in timestamps if t > cutoff]
    if len(timestamps) >= max_requests:
        _in_memory_buckets[key] = timestamps
        return False

    timestamps.append(now)
    _in_memory_buckets[key] = timestamps
    return True


def get_client_ip(request: Request) -> str:
    """Extract client IP handling forward headers carefully."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first untrusted IP in the list
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"
