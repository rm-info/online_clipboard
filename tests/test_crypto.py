"""
tests/test_crypto.py — Unit tests for the crypto module
"""

import os
import secrets
import pytest

# Set required env var before importing the module
os.environ["CLIPBOARD_SERVER_SECRET"] = secrets.token_hex(32)

from app.crypto import decrypt, decrypt_bytes, derive_key, encrypt, encrypt_bytes, generate_session_id
from cryptography.exceptions import InvalidTag


# ---------------------------------------------------------------------------
# Session ID generation
# ---------------------------------------------------------------------------

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
        # Generating 100 IDs should yield no duplicates (statistically)
        ids = {generate_session_id() for _ in range(100)}
        assert len(ids) > 90  # Generous threshold for 5-char IDs


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    @pytest.fixture(params=["", "simple", "p@$$w0rd!🔐", "a" * 50])
    def password(self, request):
        return request.param

    @pytest.fixture(params=[False, True])
    def sid(self, request):
        return generate_session_id(secure_mode=request.param)

    @pytest.fixture
    def key(self, sid, password):
        return derive_key(sid, password)

    def test_roundtrip(self, key):
        plaintext = "Hello, clipboard!"
        token = encrypt(plaintext, key)
        assert decrypt(token, key) == plaintext

    def test_unicode_roundtrip(self, key):
        plaintext = "こんにちは 🌍 مرحبا"
        assert decrypt(encrypt(plaintext, key), key) == plaintext

    def test_wrong_key_rejected(self, sid, password, key):
        wrong_key = derive_key(sid, password + "_wrong")
        token = encrypt("secret", key)
        with pytest.raises((InvalidTag, Exception)):
            decrypt(token, wrong_key)

    def test_wrong_session_rejected(self, password):
        sid1 = generate_session_id()
        sid2 = generate_session_id()
        key1 = derive_key(sid1, password)
        key2 = derive_key(sid2, password)
        token = encrypt("secret", key1)
        with pytest.raises((InvalidTag, Exception)):
            decrypt(token, key2)

    def test_tampered_token_rejected(self, key):
        token = encrypt("secret", key)
        # Flip a byte in the ciphertext portion
        parts = token.split(":")
        tampered = parts[0] + ":" + parts[1][:-4] + "XXXX"
        with pytest.raises(Exception):
            decrypt(tampered, key)

    def test_each_encryption_unique(self, key):
        # Same plaintext encrypted twice should produce different tokens (random nonce)
        t1 = encrypt("hello", key)
        t2 = encrypt("hello", key)
        assert t1 != t2

    def test_empty_plaintext_raises(self, key):
        with pytest.raises(ValueError):
            encrypt("", key)

    def test_malformed_token_raises(self, key):
        with pytest.raises(ValueError):
            decrypt("not_a_valid_token", key)

    def test_binary_roundtrip(self, key):
        payload = b"\x00\x01binary-data\xff"
        token = encrypt_bytes(payload, key)
        assert decrypt_bytes(token, key) == payload

    def test_binary_wrong_key_rejected(self, sid, password, key):
        wrong_key = derive_key(sid, password + "_wrong")
        token = encrypt_bytes(b"secret-bytes", key)
        with pytest.raises((InvalidTag, Exception)):
            decrypt_bytes(token, wrong_key)

    def test_binary_empty_payload_raises(self, key):
        with pytest.raises(ValueError):
            encrypt_bytes(b"", key)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_deterministic(self):
        k1 = derive_key("abc12", "password")
        k2 = derive_key("abc12", "password")
        assert k1 == k2

    def test_different_password_different_key(self):
        assert derive_key("abc12", "pass1") != derive_key("abc12", "pass2")

    def test_different_session_different_key(self):
        assert derive_key("sid01", "pass") != derive_key("sid02", "pass")

    def test_key_length(self):
        assert len(derive_key("abc12", "pass")) == 32
