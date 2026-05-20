"""
pow.py — Proof-of-work challenge issuance and verification.
============================================================

Without IP tracking we lose the natural anti-abuse signal. PoW puts a CPU
cost on each session create / auth attempt: legit users pay ~500ms once
per action, automated bulk attackers pay the same per request, which is
plenty to make spam unprofitable.

Protocol:
    1. Client GETs /pow/challenge → {challenge, difficulty}
    2. Server stores `pow:{challenge}` → "1" in Redis with a short TTL
    3. Client finds nonce s.t. SHA256(challenge + ":" + nonce) has
       `difficulty` leading zero bits
    4. Client POSTs the protected endpoint with challenge + nonce
    5. Server verifies the hash, then CAS-deletes the challenge so it
       can't be reused

Difficulty is in *bits* of zero prefix. 18 bits ≈ 262k hashes (~0.5s on a
modern CPU). Tune via POW_DIFFICULTY_BITS env var.
"""

import hashlib
import secrets
from typing import Tuple

from session import get_redis


def _key(challenge: str) -> str:
    return f"pow:{challenge}"


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        mask = 0x80
        while mask and (byte & mask) == 0:
            bits += 1
            mask >>= 1
        return bits
    return bits


async def issue_challenge(difficulty: int, ttl_seconds: int = 120) -> Tuple[str, int]:
    """Mint a fresh challenge token and remember it so the solution is
    single-use. `ttl_seconds` is the window the client has to solve.
    """
    challenge = secrets.token_hex(16)
    r = await get_redis()
    await r.set(_key(challenge), "1", ex=ttl_seconds)
    return challenge, difficulty


async def consume(challenge: str, nonce: str, difficulty: int) -> bool:
    """Verify a (challenge, nonce) pair, single-use. Returns True iff:
      - challenge exists in Redis (issued and not yet consumed)
      - SHA256(challenge + ":" + nonce) starts with `difficulty` zero bits
    On success the challenge is deleted, so a replay returns False.
    """
    if not challenge or not nonce:
        return False
    r = await get_redis()
    if not await r.exists(_key(challenge)):
        return False
    digest = hashlib.sha256(f"{challenge}:{nonce}".encode("utf-8")).digest()
    if _leading_zero_bits(digest) < difficulty:
        return False
    deleted = await r.delete(_key(challenge))
    return deleted == 1
