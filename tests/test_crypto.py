"""
tests/test_crypto.py — Unit tests for the server-side crypto module.

In v2 the server's crypto.py only owns the session-ID generator (everything
else moved to the browser). What remains to test is randomness and the
character set.
"""

import os
import secrets

os.environ.setdefault("CLIPBOARD_SERVER_SECRET", secrets.token_hex(32))

from app.crypto import generate_session_id


class TestGenerateSessionId:
    def test_short_length(self):
        sid = generate_session_id(secure_mode=False)
        assert len(sid) == 5

    def test_long_length(self):
        sid = generate_session_id(secure_mode=True)
        assert len(sid) == 50

    def test_only_safe_chars(self):
        safe = set("23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ")
        for _ in range(50):
            sid = generate_session_id()
            assert all(c in safe for c in sid)

    def test_randomness(self):
        ids = {generate_session_id() for _ in range(100)}
        assert len(ids) > 90
