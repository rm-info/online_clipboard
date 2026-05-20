"""
crypto.py — Server-side crypto helpers (E2EE mode).
====================================================

In v2 the server no longer derives keys, encrypts, or decrypts. All AES-GCM
and Argon2id operations happen in the browser (see static/js/clip-crypto.js).
What's left here is the random session ID generator, which is server-side
because the server checks for ID collisions in Redis.
"""

import secrets

# Characters allowed in session IDs: uppercase, lowercase, digits.
# Avoids visually ambiguous chars (0/O, 1/l/I) for the short 5-char mode.
_SAFE_CHARS = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ"


def generate_session_id(secure_mode: bool = False) -> str:
    """Cryptographically random session ID.

    - Normal mode:  5 characters  (~916M combinations)
    - Secure mode: 50 characters  (astronomically large space)
    """
    length = 50 if secure_mode else 5
    return "".join(secrets.choice(_SAFE_CHARS) for _ in range(length))
