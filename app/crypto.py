"""
crypto.py — Encryption/Decryption core for Online Clipboard
============================================================

Security model:
- AES-256-GCM for authenticated encryption (confidentiality + integrity)
- Argon2id for key derivation (resistant to brute-force and GPU attacks)
- Key = Argon2id(password, salt=session_id, pepper=SERVER_SECRET)
- Even without a password, the SERVER_SECRET ensures DB leaks don't expose data
- Each piece of data gets a unique random nonce (96-bit), stored alongside ciphertext
"""

import base64
import os
import secrets
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Argon2id parameters — tuned for interactive use (fast enough, hard to brute-force)
# Increase ARGON2_TIME_COST / ARGON2_MEMORY_COST for higher security at the cost of speed
ARGON2_TIME_COST   = 2          # number of iterations
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN    = 32         # 256-bit key for AES-256

AES_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM (NIST recommended)


# ---------------------------------------------------------------------------
# Server secret — loaded once at startup from environment
# ---------------------------------------------------------------------------

def _load_server_secret() -> bytes:
    """
    Load the server-side pepper from the environment.
    This secret ensures that even a full Redis dump is useless without it.
    Must be a hex-encoded 32-byte (64 hex chars) random value.

    Generate with:
        python -c "import secrets; print(secrets.token_hex(32))"
    """
    raw = os.environ.get("CLIPBOARD_SERVER_SECRET", "")
    if not raw or len(raw) < 32:
        raise EnvironmentError(
            "CLIPBOARD_SERVER_SECRET is missing or too short. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        return bytes.fromhex(raw)
    except ValueError:
        raise EnvironmentError("CLIPBOARD_SERVER_SECRET must be a valid hex string.")


SERVER_SECRET: bytes = _load_server_secret()


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------

def derive_key(session_id: str, password: str) -> bytes:
    """
    Derive a 256-bit AES key from the session ID, password, and server secret.

    - session_id acts as the Argon2 salt (unique per session, not secret)
    - password is the user-provided secret (may be empty string)
    - SERVER_SECRET is the pepper (server-side, never stored in Redis)

    Even with password="" the key is non-trivial because of SERVER_SECRET.
    An attacker with Redis access AND the source code still can't decrypt
    without the SERVER_SECRET from the server's environment.
    """
    # Combine password and server secret as the "secret" input to Argon2
    # This way the server secret acts as a true pepper
    secret_material: bytes = password.encode("utf-8") + SERVER_SECRET

    # session_id is the salt — must be bytes, at least 8 bytes for Argon2
    salt: bytes = session_id.encode("utf-8")
    # Pad salt to at least 8 bytes if session_id is short (e.g. 5-char default)
    if len(salt) < 8:
        salt = salt.ljust(8, b"\x00")

    key: bytes = hash_secret_raw(
        secret=secret_material,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,  # Argon2id = best of Argon2i and Argon2d
    )
    return key


# ---------------------------------------------------------------------------
# Encryption / Decryption
# ---------------------------------------------------------------------------

def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt a plaintext string with a pre-derived 32-byte AES key.

    Token format (all base64url, colon-separated):
        <nonce_b64>:<ciphertext_with_tag_b64>

    The GCM authentication tag (16 bytes) is appended to the ciphertext
    automatically by the cryptography library.

    Caller is responsible for obtaining `key` via derive_key() once per
    session — running Argon2id per encrypt call was needlessly expensive.

    Raises:
        ValueError: if plaintext is empty
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty plaintext.")

    nonce  = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)

    ciphertext_with_tag: bytes = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    nonce_b64      = base64.urlsafe_b64encode(nonce).decode()
    ciphertext_b64 = base64.urlsafe_b64encode(ciphertext_with_tag).decode()

    return f"{nonce_b64}:{ciphertext_b64}"


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt arbitrary bytes with a pre-derived 32-byte AES key.

    Binary token format:
        <12-byte nonce><ciphertext_with_tag>
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty plaintext.")

    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext_with_tag


def decrypt(token: str, key: bytes) -> str:
    """
    Decrypt a token produced by encrypt() using a pre-derived 32-byte key.

    Returns the original plaintext string.

    Raises:
        ValueError:  if the token format is invalid
        cryptography.exceptions.InvalidTag: if decryption fails
            (wrong key, corrupted data, or tampering detected)
    """
    try:
        nonce_b64, ciphertext_b64 = token.split(":", 1)
        nonce              = base64.urlsafe_b64decode(nonce_b64)
        ciphertext_with_tag = base64.urlsafe_b64decode(ciphertext_b64)
    except Exception:
        raise ValueError("Invalid token format.")

    aesgcm = AESGCM(key)

    # This raises InvalidTag if authentication fails — DO NOT catch this silently
    plaintext_bytes: bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes.decode("utf-8")


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    """
    Decrypt a binary token produced by encrypt_bytes() with a pre-derived key.
    """
    if len(token) <= AES_NONCE_SIZE:
        raise ValueError("Invalid binary token format.")

    nonce = token[:AES_NONCE_SIZE]
    ciphertext_with_tag = token[AES_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


# ---------------------------------------------------------------------------
# Session ID Generation
# ---------------------------------------------------------------------------

# Characters allowed in session IDs: uppercase, lowercase, digits
# Avoids visually ambiguous chars (0/O, 1/l/I) for the short 5-char mode
_SAFE_CHARS = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ"

def generate_session_id(secure_mode: bool = False) -> str:
    """
    Generate a random session ID.

    - Normal mode:  5 characters  (~916M combinations)
    - Secure mode: 50 characters  (astronomically large space)

    Uses secrets.choice() which is cryptographically secure.
    """
    length = 50 if secure_mode else 5
    return "".join(secrets.choice(_SAFE_CHARS) for _ in range(length))


# ---------------------------------------------------------------------------
# Quick self-test (run with: python crypto.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Requires CLIPBOARD_SERVER_SECRET to be set — set a test value
    os.environ.setdefault("CLIPBOARD_SERVER_SECRET", secrets.token_hex(32))

    # Reload after setting env (normally loaded at import time)
    import importlib, crypto as _self
    _self.SERVER_SECRET = _self._load_server_secret()

    print("=== crypto.py self-test ===\n")

    for secure in (False, True):
        sid = generate_session_id(secure_mode=secure)
        print(f"Session ID ({'secure' if secure else 'normal'}): {sid!r}  (len={len(sid)})")

        for pwd in ("", "hunter2", "p@$$w0rd!🔐"):
            plaintext = f"Hello, clipboard! Password={pwd!r}"
            key       = derive_key(sid, pwd)
            token     = encrypt(plaintext, key)
            recovered = decrypt(token, key)

            assert recovered == plaintext, "DECRYPTION MISMATCH"
            print(f"  ✓ password={pwd!r:20s}  token_len={len(token)}")

            # Confirm wrong key (derived from wrong password) raises an error
            wrong_key = derive_key(sid, pwd + "WRONG")
            try:
                decrypt(token, wrong_key)
                print("  ✗ Wrong key should have raised — SECURITY FAILURE")
                sys.exit(1)
            except Exception:
                print(f"  ✓ Wrong key correctly rejected")

        print()

    print("All tests passed ✓")
