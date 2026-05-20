"""
security.py — Per-session and per-token rate limiting (anon mode).
===================================================================

In v2 there is no IP tracking. Two layers replace the v1 IP-based logic:

  * Per-session failed auth counter (still uses Redis, but keyed by sid not
    IP) — keeps the "20 wrong tries → session locked forever" behaviour.
  * Per-write-token bucket — caps how many writes a single browser session
    can issue in a sliding window. Keyed by the signed token cookie value.

Anyone who clears cookies gets a fresh token but has to solve PoW again to
re-enter, so the bucket can't be reset for free.
"""

import hashlib

from config import (
    SESSION_MAX_FAILED_ATTEMPTS,
    SESSION_TTL_SECONDS,
    WRITE_RATE_LIMIT_MAX,
    WRITE_RATE_LIMIT_WINDOW_SECONDS,
)
from session import get_redis


def _key_session_failed(sid: str) -> str:
    return f"session:{sid}:failed"


def _key_write_bucket(token_hash: str) -> str:
    return f"writebucket:{token_hash}"


def _hash_token(token: str) -> str:
    # SHA-256 of the token keeps the Redis key short and avoids leaking the
    # token's structure into Redis keys.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]


async def record_failed_auth(sid: str) -> int:
    """Bump the per-session failed-auth counter. Returns the new value."""
    r = await get_redis()
    failures = await r.incr(_key_session_failed(sid))
    await r.expire(_key_session_failed(sid), SESSION_TTL_SECONDS)
    return failures


async def clear_failed_auth(sid: str) -> None:
    r = await get_redis()
    await r.delete(_key_session_failed(sid))


async def session_should_lock(sid: str) -> bool:
    r = await get_redis()
    val = await r.get(_key_session_failed(sid))
    return int(val) >= SESSION_MAX_FAILED_ATTEMPTS if val else False


async def check_write_quota(token: str) -> tuple[bool, int]:
    """Per-token sliding-window quota for write endpoints.

    Returns (allowed, retry_after_seconds). Setting WRITE_RATE_LIMIT_MAX <= 0
    disables the check.
    """
    if WRITE_RATE_LIMIT_MAX <= 0:
        return True, 0
    r = await get_redis()
    key = _key_write_bucket(_hash_token(token))
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, WRITE_RATE_LIMIT_WINDOW_SECONDS)
    if count > WRITE_RATE_LIMIT_MAX:
        ttl = await r.ttl(key)
        return False, max(1, ttl)
    return True, 0
