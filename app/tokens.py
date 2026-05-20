"""
tokens.py — HMAC-signed write tokens for E2EE-mode authorization.
==================================================================

The server never sees the user's key in E2EE mode, so the old "key-in-cookie"
auth pattern is gone. Instead, after a client proves possession of the
session key via the auth handshake (see /{sid}/auth in main.py), we hand
out a short-lived HMAC-signed token bound to the session ID. That token
travels in an httponly cookie and is required for every write endpoint.

Token format (compact, no JSON):
    {sid}|{expires_at_unix}.{hex_hmac_sha256}

Forging requires the server pepper (CLIPBOARD_SERVER_SECRET) — the same env
var that used to pepper Argon2id; it's been repurposed as the HMAC key.
"""

import hashlib
import hmac
import time
from typing import Optional

from config import SERVER_SECRET, SESSION_TTL_SECONDS


def _hmac_hex(body: str) -> str:
    return hmac.new(SERVER_SECRET, body.encode("utf-8"), hashlib.sha256).hexdigest()


def issue(sid: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
    """Mint a fresh token bound to `sid`, valid for `ttl_seconds` from now."""
    expires_at = int(time.time()) + int(ttl_seconds)
    body = f"{sid}|{expires_at}"
    return f"{body}.{_hmac_hex(body)}"


def verify(token: str, sid: str) -> Optional[int]:
    """Return remaining seconds if valid for `sid` and not expired, else None.

    Constant-time comparison protects the HMAC check; sid check is plain
    equality (sid isn't a secret).
    """
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    expected = _hmac_hex(body)
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        tok_sid, expires_str = body.split("|", 1)
        expires_at = int(expires_str)
    except ValueError:
        return None
    if tok_sid != sid:
        return None
    remaining = expires_at - int(time.time())
    return remaining if remaining > 0 else None
