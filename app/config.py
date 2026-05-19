"""
config.py — Centralized configuration loaded from environment variables
"""

import os


def _require_env(key: str, min_len: int = 1) -> str:
    val = os.environ.get(key, "")
    if len(val) < min_len:
        raise EnvironmentError(
            f"Environment variable '{key}' is missing or too short (min {min_len} chars).\n"
            f"Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return val


# ---------------------------------------------------------------------------
# Server secret (pepper for encryption)
# ---------------------------------------------------------------------------
SERVER_SECRET: bytes = bytes.fromhex(
    _require_env("CLIPBOARD_SERVER_SECRET", min_len=64)
)

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# ---------------------------------------------------------------------------
# Session settings
# ---------------------------------------------------------------------------
SESSION_TTL_SECONDS: int = int(os.environ.get("SESSION_TTL_SECONDS", 7200))  # 2 hours
SESSION_ID_SHORT_LEN: int = 5
SESSION_ID_LONG_LEN: int = 50
FILE_MAX_SIZE_BYTES: int = int(os.environ.get("FILE_MAX_SIZE_BYTES", 100 * 1024 * 1024))
SESSION_FILE_MAX_BYTES: int = int(
    os.environ.get("SESSION_FILE_MAX_BYTES", 1024 * 1024 * 1024)
)
# Global cap across all sessions. Acts as the operator's disk budget for uploads.
TOTAL_FILE_MAX_BYTES: int = int(
    os.environ.get("TOTAL_FILE_MAX_BYTES", 10 * 1024 * 1024 * 1024)
)
# How often the background task purges expired session directories from disk.
CLEANUP_INTERVAL_SECONDS: int = int(os.environ.get("CLEANUP_INTERVAL_SECONDS", 600))
# /healthz returns 503 when disk usage ratio reaches this threshold (0.0–1.0).
HEALTHZ_WARN_RATIO: float = float(os.environ.get("HEALTHZ_WARN_RATIO", 0.8))
UPLOAD_ROOT: str = os.environ.get("UPLOAD_ROOT", "/tmp/online_clipboard_uploads")

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
RATE_LIMIT_MAX_ATTEMPTS: int = int(os.environ.get("RATE_LIMIT_MAX_ATTEMPTS", 10))
RATE_LIMIT_WINDOW_SECONDS: int = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 300))   # 5 min
RATE_LIMIT_BAN_SECONDS: int = int(os.environ.get("RATE_LIMIT_BAN_SECONDS", 3600))        # 1 hour temp ban
RATE_LIMIT_PERM_BAN_THRESHOLD: int = int(os.environ.get("RATE_LIMIT_PERM_BAN_THRESHOLD", 3))  # temp bans before perma

# Max failed attempts on a single session before it's locked forever
SESSION_MAX_FAILED_ATTEMPTS: int = int(os.environ.get("SESSION_MAX_FAILED_ATTEMPTS", 20))

# Per-IP quotas on POST / and POST /{sid}/upload. Set max <= 0 to disable.
CREATE_RATE_LIMIT_MAX: int = int(os.environ.get("CREATE_RATE_LIMIT_MAX", 30))
CREATE_RATE_LIMIT_WINDOW_SECONDS: int = int(
    os.environ.get("CREATE_RATE_LIMIT_WINDOW_SECONDS", 3600)
)
UPLOAD_RATE_LIMIT_MAX: int = int(os.environ.get("UPLOAD_RATE_LIMIT_MAX", 60))
UPLOAD_RATE_LIMIT_WINDOW_SECONDS: int = int(
    os.environ.get("UPLOAD_RATE_LIMIT_WINDOW_SECONDS", 3600)
)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
APP_VERSION: str = os.environ.get("APP_VERSION", "1.1.0")

# SSE (Server-Sent Events) for real-time sync.
# Set to false on shared hosting (Passenger queue saturation).
# Fallback: polling every 10s.
SSE_ENABLED: bool = os.environ.get("SSE_ENABLED", "true").lower() == "true"
DEBUG: bool = os.environ.get("DEBUG", "false").lower() == "true"
APP_HOST: str = os.environ.get("APP_HOST", "0.0.0.0")
APP_PORT: int = int(os.environ.get("APP_PORT", 8000))
