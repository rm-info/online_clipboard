"""
session.py — Session management backed by Redis (E2EE mode).
============================================================

Redis key schema (v2):
  session:{sid}:meta          HASH   { has_password, created_at, expires_at,
                                       verifier, auth_anchor }
  session:{sid}:items         LIST   [ ciphertext_token, ... ]
  session:{sid}:item_meta     HASH   { item_id: json_meta }     # opaque metadata
  session:{sid}:item_order    LIST   [ item_id, ... ]
  session:{sid}:files         HASH   { file_id: json_meta }
  session:{sid}:file_order    LIST   [ file_id, ... ]
  session:{sid}:entries       LIST   [ "text:item_id" | "file:file_id", ... ]
  session:{sid}:file_bytes    STRING integer counter
  session:{sid}:failed        STRING integer counter (failed auth proofs)
  session:{sid}:locked        STRING "1"  (permanent lock flag)

The server never sees plaintext. Items are stored as opaque ciphertext
tokens produced by the browser. Files live on disk as opaque binary blobs.
Filenames are themselves ciphertext, posted by the client during upload.
"""

import asyncio
import errno
import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import AsyncIterator, Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

from config import (
    CLEANUP_INTERVAL_SECONDS,
    FILE_MAX_SIZE_BYTES,
    REDIS_URL,
    SESSION_FILE_MAX_BYTES,
    SESSION_TTL_SECONDS,
    TOTAL_FILE_MAX_BYTES,
    UPLOAD_ROOT,
)
from crypto import generate_session_id


_redis: Optional[aioredis.Redis] = None
_upload_root = Path(UPLOAD_ROOT)


def _now() -> int:
    return int(time.time())


def _session_dir(sid: str) -> Path:
    return _upload_root / sid


def _expiry_marker_path(sid: str) -> Path:
    return _session_dir(sid) / ".expires_at"


def _channel(sid: str) -> str:
    return f"session:{sid}:notify"


def _key_meta(sid: str) -> str:
    return f"session:{sid}:meta"


def _key_items(sid: str) -> str:
    return f"session:{sid}:items"


def _key_item_meta(sid: str) -> str:
    return f"session:{sid}:item_meta"


def _key_item_order(sid: str) -> str:
    return f"session:{sid}:item_order"


def _key_files(sid: str) -> str:
    return f"session:{sid}:files"


def _key_file_order(sid: str) -> str:
    return f"session:{sid}:file_order"


def _key_entries(sid: str) -> str:
    return f"session:{sid}:entries"


def _key_file_bytes(sid: str) -> str:
    return f"session:{sid}:file_bytes"


def _key_failed(sid: str) -> str:
    return f"session:{sid}:failed"


def _key_locked(sid: str) -> str:
    return f"session:{sid}:locked"


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis:
        await _redis.aclose()
        _redis = None


def _ensure_upload_root() -> None:
    _upload_root.mkdir(parents=True, exist_ok=True)


def _write_expiry_marker(sid: str, expires_at: int) -> None:
    session_dir = _session_dir(sid)
    session_dir.mkdir(parents=True, exist_ok=True)
    _expiry_marker_path(sid).write_text(str(expires_at), encoding="utf-8")


def _cleanup_session_dir(sid: str) -> None:
    shutil.rmtree(_session_dir(sid), ignore_errors=True)


def cleanup_expired_upload_dirs() -> None:
    _ensure_upload_root()
    now = _now()
    for entry in _upload_root.iterdir():
        if not entry.is_dir():
            continue

        marker = entry / ".expires_at"
        try:
            expires_at = int(marker.read_text(encoding="utf-8").strip())
        except (FileNotFoundError, ValueError, OSError):
            continue

        if expires_at <= now:
            shutil.rmtree(entry, ignore_errors=True)


def global_used_bytes() -> int:
    """Sum of all ciphertext file sizes currently under UPLOAD_ROOT."""
    _ensure_upload_root()
    total = 0
    for path in _upload_root.rglob("*.bin"):
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


async def periodic_cleanup_loop(interval_seconds: int = CLEANUP_INTERVAL_SECONDS) -> None:
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            cleanup_expired_upload_dirs()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("periodic_cleanup_loop iteration failed")


async def _refresh_ttl(r: aioredis.Redis, sid: str) -> None:
    expires_at = _now() + SESSION_TTL_SECONDS
    await r.hset(_key_meta(sid), mapping={"expires_at": str(expires_at)})
    for key in (
        _key_meta(sid),
        _key_items(sid),
        _key_item_meta(sid),
        _key_item_order(sid),
        _key_files(sid),
        _key_file_order(sid),
        _key_entries(sid),
        _key_file_bytes(sid),
        _key_failed(sid),
    ):
        await r.expire(key, SESSION_TTL_SECONDS)
    _write_expiry_marker(sid, expires_at)


def _load_meta(raw_meta: str) -> dict:
    meta = json.loads(raw_meta)
    for field in ("size", "created_at", "uploaded_at"):
        if field in meta:
            meta[field] = int(meta[field])
    return meta


def _entry_ref(kind: str, entry_id: str) -> str:
    return f"{kind}:{entry_id}"


def _make_text_meta(item_id: str, size: int, secret: bool = False) -> dict:
    return {"id": item_id, "size": size, "created_at": _now(), "secret": bool(secret)}


def _make_file_meta(
    file_id: str,
    encrypted_name: str,
    stored_name: str,
    size: int,
    has_thumb: bool = False,
) -> dict:
    return {
        "id": file_id,
        "encrypted_name": encrypted_name,
        "stored_name": stored_name,
        "size": int(size),
        "uploaded_at": _now(),
        "has_thumb": bool(has_thumb),
    }


_THUMB_SUFFIX = ".thumb.bin"


def _thumb_name_for(stored_name: str) -> str:
    return stored_name.replace(".bin", _THUMB_SUFFIX)


async def _append_text_entry(
    r: aioredis.Redis,
    sid: str,
    ciphertext: str,
    plain_size: int,
    secret: bool = False,
) -> dict:
    item_id = uuid.uuid4().hex
    meta = _make_text_meta(item_id, plain_size, secret=secret)

    async with r.pipeline(transaction=True) as pipe:
        pipe.rpush(_key_items(sid), ciphertext)
        pipe.hset(_key_item_meta(sid), item_id, json.dumps(meta))
        pipe.rpush(_key_item_order(sid), item_id)
        pipe.rpush(_key_entries(sid), _entry_ref("text", item_id))
        await pipe.execute()

    return meta


async def create_session(
    first_item_ct: str,
    first_item_size: int,
    has_password: bool,
    salt: str,
    verifier_blob: str,
    auth_anchor: str,
    secure_mode: bool = False,
    secret: bool = False,
) -> str:
    """Allocate a fresh session ID and persist the auth anchors + first item.

    The server never sees the user's key, password, or plaintext. The client
    chooses an Argon2id salt at session creation (random bytes, base64) so
    that key derivation is independent of the server-allocated session ID.
    Stored in `meta.salt` and returned at /verifier time so a returning
    visitor can rederive the same key from the same password.
    """
    r = await get_redis()
    cleanup_expired_upload_dirs()

    for _ in range(5):
        sid = generate_session_id(secure_mode=secure_mode)

        async with r.pipeline(transaction=True) as pipe:
            pipe.hsetnx(_key_meta(sid), "has_password", "1" if has_password else "0")
            pipe.hsetnx(_key_meta(sid), "created_at", str(_now()))
            pipe.hsetnx(_key_meta(sid), "salt", salt)
            pipe.hsetnx(_key_meta(sid), "verifier", verifier_blob)
            pipe.hsetnx(_key_meta(sid), "auth_anchor", auth_anchor)
            results = await pipe.execute()

        if not results[0]:
            continue

        await _append_text_entry(r, sid, first_item_ct, first_item_size, secret=secret)
        await r.set(_key_file_bytes(sid), 0, ex=SESSION_TTL_SECONDS)
        await _refresh_ttl(r, sid)
        return sid

    raise RuntimeError("Could not generate a unique session ID after 5 attempts.")


async def session_exists(sid: str) -> bool:
    r = await get_redis()
    exists = bool(await r.exists(_key_meta(sid)))
    if not exists:
        _cleanup_session_dir(sid)
    return exists


async def session_is_locked(sid: str) -> bool:
    r = await get_redis()
    return bool(await r.exists(_key_locked(sid)))


async def session_has_password(sid: str) -> bool:
    r = await get_redis()
    val = await r.hget(_key_meta(sid), "has_password")
    return val == "1"


async def get_session_expires_at(sid: str) -> Optional[int]:
    r = await get_redis()
    val = await r.hget(_key_meta(sid), "expires_at")
    return int(val) if val else None


async def get_session_file_bytes(sid: str) -> int:
    r = await get_redis()
    raw = await r.get(_key_file_bytes(sid))
    return int(raw) if raw else 0


async def get_verifier_blob(sid: str) -> Optional[str]:
    """Return the encrypted verifier blob for client-side decryption.

    The blob is what the browser needs to confirm the user's typed password
    yields the correct key. It's ciphertext, so serving it to an unauth'd
    visitor doesn't leak anything beyond "this session uses E2EE".
    """
    r = await get_redis()
    return await r.hget(_key_meta(sid), "verifier")


async def get_salt(sid: str) -> Optional[str]:
    """Return the client-chosen Argon2id salt for this session."""
    r = await get_redis()
    return await r.hget(_key_meta(sid), "salt")


async def get_auth_anchor(sid: str) -> Optional[str]:
    r = await get_redis()
    return await r.hget(_key_meta(sid), "auth_anchor")


async def lock_session_forever(sid: str) -> None:
    r = await get_redis()
    await r.set(_key_locked(sid), "1", ex=SESSION_TTL_SECONDS * 24)
    await r.delete(
        _key_meta(sid),
        _key_items(sid),
        _key_item_meta(sid),
        _key_item_order(sid),
        _key_files(sid),
        _key_file_order(sid),
        _key_entries(sid),
        _key_file_bytes(sid),
        _key_failed(sid),
    )
    _cleanup_session_dir(sid)


async def delete_session(sid: str, wiped: bool = False) -> None:
    r = await get_redis()
    if wiped:
        await r.publish(_channel(sid), "session_wiped")
    await r.delete(
        _key_meta(sid),
        _key_items(sid),
        _key_item_meta(sid),
        _key_item_order(sid),
        _key_files(sid),
        _key_file_order(sid),
        _key_entries(sid),
        _key_file_bytes(sid),
        _key_failed(sid),
        _key_locked(sid),
    )
    _cleanup_session_dir(sid)


async def add_item(sid: str, ciphertext: str, plain_size: int, secret: bool = False) -> None:
    r = await get_redis()
    await _append_text_entry(r, sid, ciphertext, plain_size, secret=secret)
    await _refresh_ttl(r, sid)
    await r.publish(_channel(sid), "new_item")


async def delete_item(sid: str, item_id: str) -> bool:
    r = await get_redis()

    if not await r.hexists(_key_item_meta(sid), item_id):
        return False

    idx = await r.lpos(_key_item_order(sid), item_id)
    token = await r.lindex(_key_items(sid), idx) if idx is not None else None

    async with r.pipeline(transaction=True) as pipe:
        pipe.hdel(_key_item_meta(sid), item_id)
        pipe.lrem(_key_item_order(sid), 1, item_id)
        pipe.lrem(_key_entries(sid), 1, _entry_ref("text", item_id))
        if token is not None:
            pipe.lrem(_key_items(sid), 1, token)
        await pipe.execute()

    await r.publish(_channel(sid), "item_deleted")
    return True


async def delete_file(sid: str, file_id: str) -> bool:
    r = await get_redis()

    raw_meta = await r.hget(_key_files(sid), file_id)
    if not raw_meta:
        return False

    meta = _load_meta(raw_meta)
    stored_name = meta.get("stored_name")
    on_disk_size = 0
    if stored_name:
        try:
            on_disk_size = (_session_dir(sid) / stored_name).stat().st_size
        except OSError:
            on_disk_size = 0

    async with r.pipeline(transaction=True) as pipe:
        pipe.hdel(_key_files(sid), file_id)
        pipe.lrem(_key_file_order(sid), 1, file_id)
        pipe.lrem(_key_entries(sid), 1, _entry_ref("file", file_id))
        if on_disk_size > 0:
            pipe.decrby(_key_file_bytes(sid), on_disk_size)
        await pipe.execute()

    if stored_name:
        try:
            (_session_dir(sid) / stored_name).unlink(missing_ok=True)
            (_session_dir(sid) / _thumb_name_for(stored_name)).unlink(missing_ok=True)
        except OSError:
            pass

    await r.publish(_channel(sid), "file_deleted")
    return True


async def touch_session(sid: str) -> None:
    r = await get_redis()
    if await r.exists(_key_meta(sid)):
        await _refresh_ttl(r, sid)


async def save_file(
    sid: str,
    encrypted_name: str,
    plain_size: int,
    ciphertext: bytes,
    thumb_ciphertext: Optional[bytes] = None,
) -> dict:
    """Persist a client-encrypted file blob and optional encrypted thumbnail.

    `encrypted_name` is the AES-GCM token of the original filename; the
    server stores it opaquely. `plain_size` is the client-claimed plaintext
    size in bytes (used for UI display + quota math). The actual on-disk
    ciphertext size is what counts against the quota — there's a small
    AES-GCM overhead (12 nonce + 16 tag = 28 bytes per blob).
    """
    if not encrypted_name:
        raise ValueError("Filename token is required.")

    size = len(ciphertext)
    if size <= 0:
        raise ValueError("File cannot be empty.")
    if size > FILE_MAX_SIZE_BYTES:
        raise ValueError("File too large.")

    r = await get_redis()
    current_total = await get_session_file_bytes(sid)
    new_total = current_total + size
    if new_total > SESSION_FILE_MAX_BYTES:
        raise ValueError("Session file quota exceeded.")

    cleanup_expired_upload_dirs()

    total_new_disk = size + (len(thumb_ciphertext) if thumb_ciphertext else 0)
    if global_used_bytes() + total_new_disk > TOTAL_FILE_MAX_BYTES:
        raise ValueError("Service quota exceeded.")

    file_id = uuid.uuid4().hex
    session_dir = _session_dir(sid)
    session_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{file_id}.bin"
    file_path = session_dir / stored_name
    thumb_path = session_dir / _thumb_name_for(stored_name)
    has_thumb = False
    try:
        with file_path.open("wb") as handle:
            handle.write(ciphertext)
        if thumb_ciphertext is not None:
            try:
                with thumb_path.open("wb") as handle:
                    handle.write(thumb_ciphertext)
                has_thumb = True
            except OSError:
                thumb_path.unlink(missing_ok=True)
                has_thumb = False
    except OSError as exc:
        file_path.unlink(missing_ok=True)
        thumb_path.unlink(missing_ok=True)
        if exc.errno == errno.ENOSPC:
            raise ValueError("Disk full.") from exc
        raise

    meta = _make_file_meta(file_id, encrypted_name, stored_name, plain_size, has_thumb=has_thumb)

    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(_key_files(sid), file_id, json.dumps(meta))
        pipe.rpush(_key_file_order(sid), file_id)
        pipe.rpush(_key_entries(sid), _entry_ref("file", file_id))
        pipe.set(_key_file_bytes(sid), new_total, ex=SESSION_TTL_SECONDS)
        await pipe.execute()

    await _refresh_ttl(r, sid)
    await r.publish(_channel(sid), "new_file")
    return {
        "id": meta["id"],
        "encrypted_name": meta["encrypted_name"],
        "size": meta["size"],
        "uploaded_at": meta["uploaded_at"],
        "has_thumb": meta["has_thumb"],
    }


async def get_session_contents(sid: str) -> dict:
    """Return all ciphertext blobs and metadata for the session. Server
    never decrypts — the client is responsible for rendering plaintext.
    """
    r = await get_redis()
    entry_refs = await r.lrange(_key_entries(sid), 0, -1)
    item_ids = await r.lrange(_key_item_order(sid), 0, -1)
    item_tokens = await r.lrange(_key_items(sid), 0, -1)
    file_ids = await r.lrange(_key_file_order(sid), 0, -1)

    raw_item_meta = await r.hmget(_key_item_meta(sid), item_ids) if item_ids else []
    raw_file_meta = await r.hmget(_key_files(sid), file_ids) if file_ids else []

    item_entries: dict[str, dict] = {}
    for item_id, token, meta_raw in zip(item_ids, item_tokens, raw_item_meta):
        if not meta_raw:
            continue
        meta = _load_meta(meta_raw)
        item_entries[item_id] = {
            "id": item_id,
            "type": "text",
            "ciphertext": token,
            "size": meta["size"],
            "created_at": meta["created_at"],
            "secret": bool(meta.get("secret", False)),
        }

    file_entries: dict[str, dict] = {}
    for file_id, meta_raw in zip(file_ids, raw_file_meta):
        if not meta_raw:
            continue
        meta = _load_meta(meta_raw)
        file_entries[file_id] = {
            "id": file_id,
            "type": "file",
            "encrypted_name": meta.get("encrypted_name", ""),
            "size": meta["size"],
            "uploaded_at": meta["uploaded_at"],
            "has_thumb": bool(meta.get("has_thumb", False)),
        }

    entries = []
    for ref in entry_refs:
        kind, _, entry_id = ref.partition(":")
        if kind == "text" and entry_id in item_entries:
            entries.append(item_entries[entry_id])
        if kind == "file" and entry_id in file_entries:
            entries.append(file_entries[entry_id])

    file_bytes = await get_session_file_bytes(sid)
    # expires_at lets clients (CLI, future SDKs) display the real session TTL
    # without inferring it from cookie max-age, which slides on every authenticated
    # request including reads and doesn't track session lifetime accurately.
    expires_at = await get_session_expires_at(sid)
    return {"entries": entries, "file_bytes": file_bytes, "expires_at": expires_at or 0}


async def get_file_ciphertext(sid: str, file_id: str) -> tuple[str, bytes]:
    """Return (encrypted_name, ciphertext_bytes). The client decrypts both."""
    r = await get_redis()
    raw_meta = await r.hget(_key_files(sid), file_id)
    if not raw_meta:
        raise FileNotFoundError("File not found.")

    meta = _load_meta(raw_meta)
    file_path = _session_dir(sid) / meta["stored_name"]
    if not file_path.exists():
        raise FileNotFoundError("File payload missing.")

    return meta.get("encrypted_name", ""), file_path.read_bytes()


async def get_thumb_ciphertext(sid: str, file_id: str) -> Optional[bytes]:
    """Return the encrypted thumbnail bytes, or None if no thumb was stored."""
    r = await get_redis()
    raw_meta = await r.hget(_key_files(sid), file_id)
    if not raw_meta:
        raise FileNotFoundError("File not found.")

    meta = _load_meta(raw_meta)
    if not meta.get("has_thumb"):
        return None

    thumb_path = _session_dir(sid) / _thumb_name_for(meta["stored_name"])
    if not thumb_path.exists():
        return None
    return thumb_path.read_bytes()


async def subscribe_to_session(sid: str) -> AsyncIterator[str]:
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(_channel(sid))

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                yield message["data"]

            if not await session_exists(sid):
                yield "session_expired"
                break

            if await session_is_locked(sid):
                yield "session_locked"
                break
    finally:
        await pubsub.unsubscribe(_channel(sid))
        await r.aclose()


async def verify_auth_proof(sid: str, auth_proof: str) -> bool:
    """Check that the client successfully decrypted the verifier blob.

    The client computes sha256(verifier_plaintext) — which only the holder
    of the correct key can produce — and POSTs it as `auth_proof`. We
    compare against the anchor stored at session creation.
    """
    if await session_is_locked(sid):
        return False
    anchor = await get_auth_anchor(sid)
    if not anchor:
        return False
    # Constant-time: both are hex strings of the same length.
    import hmac as _hmac
    return _hmac.compare_digest(anchor, auth_proof or "")
