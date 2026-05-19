"""
session.py — Session management backed by Redis
================================================

Redis key schema:
  session:{sid}:meta          HASH   { has_password, created_at, expires_at }
  session:{sid}:items         LIST   [ token, token, ... ]  (encrypted text payloads)
  session:{sid}:item_meta     HASH   { item_id: json_metadata }
  session:{sid}:item_order    LIST   [ item_id, item_id, ... ]
  session:{sid}:files         HASH   { file_id: json_metadata }
  session:{sid}:file_order    LIST   [ file_id, file_id, ... ]
  session:{sid}:entries       LIST   [ "text:item_id", "file:file_id", ... ]
  session:{sid}:file_bytes    STRING integer counter
  session:{sid}:failed        STRING integer counter
  session:{sid}:locked        STRING "1"  (permanent lock flag)

Files are encrypted on disk under UPLOAD_ROOT/<sid>/<file_id>.bin while Redis keeps
the metadata, ordering and quotas. Reads never refresh the TTL, only real actions do.
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
    SESSION_MAX_FAILED_ATTEMPTS,
    SESSION_TTL_SECONDS,
    TOTAL_FILE_MAX_BYTES,
    UPLOAD_ROOT,
)
from crypto import decrypt, decrypt_bytes, derive_key, encrypt, encrypt_bytes, generate_session_id


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
    """Sum of all encrypted file sizes currently under UPLOAD_ROOT.

    The filesystem is the source of truth; this avoids drift versus any
    Redis-side counter when sessions expire via TTL without explicit cleanup.
    """
    _ensure_upload_root()
    total = 0
    for path in _upload_root.rglob("*.bin"):
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


async def periodic_cleanup_loop(interval_seconds: int = CLEANUP_INTERVAL_SECONDS) -> None:
    """Background sweeper that purges expired session directories on disk.

    Redis keys already expire on their own via TTL; this only reaps the
    filesystem leftovers so disk doesn't drift upward on a low-traffic site.
    """
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


def _make_file_meta(file_id: str, filename: str, stored_name: str, size: int) -> dict:
    return {
        "id": file_id,
        "name": os.path.basename(filename),
        "stored_name": stored_name,
        "size": size,
        "uploaded_at": _now(),
    }


async def _append_text_entry(
    r: aioredis.Redis,
    sid: str,
    plaintext: str,
    key: bytes,
    secret: bool = False,
) -> dict:
    token = encrypt(plaintext, key)
    item_id = uuid.uuid4().hex
    meta = _make_text_meta(item_id, len(plaintext.encode("utf-8")), secret=secret)

    async with r.pipeline(transaction=True) as pipe:
        pipe.rpush(_key_items(sid), token)
        pipe.hset(_key_item_meta(sid), item_id, json.dumps(meta))
        pipe.rpush(_key_item_order(sid), item_id)
        pipe.rpush(_key_entries(sid), _entry_ref("text", item_id))
        await pipe.execute()

    return meta


VERIFIER_PLAINTEXT = "verifier"


async def create_session(
    first_item: str,
    password: str,
    secure_mode: bool = False,
    secret: bool = False,
) -> tuple[str, bytes]:
    """Returns (sid, key) — caller stores the key in the user's cookie."""
    r = await get_redis()
    cleanup_expired_upload_dirs()

    for _ in range(5):
        sid = generate_session_id(secure_mode=secure_mode)
        key = derive_key(sid, password)
        verifier_token = encrypt(VERIFIER_PLAINTEXT, key)
        meta = {
            "has_password": "1" if password else "0",
            "created_at": str(_now()),
            "verifier": verifier_token,
        }

        async with r.pipeline(transaction=True) as pipe:
            pipe.hsetnx(_key_meta(sid), "has_password", meta["has_password"])
            pipe.hsetnx(_key_meta(sid), "created_at", meta["created_at"])
            pipe.hsetnx(_key_meta(sid), "verifier", meta["verifier"])
            results = await pipe.execute()

        if not results[0]:
            continue

        await _append_text_entry(r, sid, first_item, key, secret=secret)
        await r.set(_key_file_bytes(sid), 0, ex=SESSION_TTL_SECONDS)
        await _refresh_ttl(r, sid)
        return sid, key

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


async def verify_password(sid: str, password: str) -> Optional[bytes]:
    """Verify the password and return the derived key on success, None on failure.

    The key is returned so the caller can place it in the session cookie —
    subsequent encrypt/decrypt calls take the key directly and skip the
    per-request Argon2id cost.
    """
    r = await get_redis()

    if await session_is_locked(sid):
        return None

    key = derive_key(sid, password)
    has_pwd = await session_has_password(sid)
    if not has_pwd:
        if password != "":
            failures = await r.incr(_key_failed(sid))
            await r.expire(_key_failed(sid), SESSION_TTL_SECONDS)
            if failures >= SESSION_MAX_FAILED_ATTEMPTS:
                await lock_session_forever(sid)
            return None
        return key

    # Try the dedicated verifier token first; fall back to the first item
    # for legacy sessions created before verifier was introduced.
    verifier = await r.hget(_key_meta(sid), "verifier")
    if not verifier:
        verifier = await r.lindex(_key_items(sid), 0)
    if not verifier:
        return None

    try:
        decrypt(verifier, key)
        await r.delete(_key_failed(sid))
        return key
    except Exception:
        failures = await r.incr(_key_failed(sid))
        await r.expire(_key_failed(sid), SESSION_TTL_SECONDS)
        if failures >= SESSION_MAX_FAILED_ATTEMPTS:
            await lock_session_forever(sid)
        return None


async def add_item(sid: str, plaintext: str, key: bytes, secret: bool = False) -> None:
    r = await get_redis()
    await _append_text_entry(r, sid, plaintext, key, secret=secret)
    await _refresh_ttl(r, sid)
    await r.publish(_channel(sid), "new_item")


async def delete_item(sid: str, item_id: str) -> bool:
    """Remove a single text item. Returns True if it existed and was removed.

    Does NOT refresh the session TTL — removing content shouldn't keep the
    session alive longer, mirroring the auth-doesnt-refresh pattern. The
    verifier in meta (set at session creation) is what gates new auths, so
    deleting all items doesn't lock anyone out.
    """
    r = await get_redis()

    if not await r.hexists(_key_item_meta(sid), item_id):
        return False

    # item_order and items are RPUSH'd in lockstep, so the index in
    # item_order is the same as in items. Read the token before mutating.
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
    """Remove a single file (Redis metadata + on-disk encrypted blob).

    Decrements the per-session file-byte counter so future uploads can reclaim
    the freed quota. Does NOT refresh the session TTL.
    """
    r = await get_redis()

    raw_meta = await r.hget(_key_files(sid), file_id)
    if not raw_meta:
        return False

    meta = _load_meta(raw_meta)
    size = int(meta.get("size", 0))
    stored_name = meta.get("stored_name")

    async with r.pipeline(transaction=True) as pipe:
        pipe.hdel(_key_files(sid), file_id)
        pipe.lrem(_key_file_order(sid), 1, file_id)
        pipe.lrem(_key_entries(sid), 1, _entry_ref("file", file_id))
        if size > 0:
            pipe.decrby(_key_file_bytes(sid), size)
        await pipe.execute()

    if stored_name:
        try:
            (_session_dir(sid) / stored_name).unlink(missing_ok=True)
        except OSError:
            pass

    await r.publish(_channel(sid), "file_deleted")
    return True


async def touch_session(sid: str) -> None:
    r = await get_redis()
    if await r.exists(_key_meta(sid)):
        await _refresh_ttl(r, sid)


async def get_items(sid: str, key: bytes) -> list[str]:
    r = await get_redis()
    tokens = await r.lrange(_key_items(sid), 0, -1)
    results = []
    for token in tokens:
        try:
            results.append(decrypt(token, key))
        except Exception:
            pass
    return results


async def save_file(sid: str, filename: str, data: bytes, key: bytes) -> dict:
    if not filename.strip():
        raise ValueError("Filename cannot be empty.")

    size = len(data)
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

    encrypted = encrypt_bytes(data, key)
    if global_used_bytes() + len(encrypted) > TOTAL_FILE_MAX_BYTES:
        raise ValueError("Service quota exceeded.")

    file_id = uuid.uuid4().hex
    session_dir = _session_dir(sid)
    session_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{file_id}.bin"
    file_path = session_dir / stored_name
    try:
        with file_path.open("wb") as handle:
            handle.write(encrypted)
    except OSError as exc:
        file_path.unlink(missing_ok=True)
        if exc.errno == errno.ENOSPC:
            raise ValueError("Disk full.") from exc
        raise

    meta = _make_file_meta(file_id, filename, stored_name, size)

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
        "name": meta["name"],
        "size": meta["size"],
        "uploaded_at": meta["uploaded_at"],
    }


async def get_files(sid: str) -> list[dict]:
    r = await get_redis()
    file_ids = await r.lrange(_key_file_order(sid), 0, -1)
    if not file_ids:
        return []

    raw_metas = await r.hmget(_key_files(sid), file_ids)
    files = []
    for raw_meta in raw_metas:
        if not raw_meta:
            continue
        meta = _load_meta(raw_meta)
        files.append(
            {
                "id": meta["id"],
                "name": meta["name"],
                "size": meta["size"],
                "uploaded_at": meta["uploaded_at"],
            }
        )
    return files


async def get_session_contents(sid: str, key: bytes) -> dict:
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
        try:
            text = decrypt(token, key)
        except Exception:
            continue
        meta = _load_meta(meta_raw)
        item_entries[item_id] = {
            "id": item_id,
            "type": "text",
            "text": text,
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
            "name": meta["name"],
            "size": meta["size"],
            "uploaded_at": meta["uploaded_at"],
        }

    entries = []
    for ref in entry_refs:
        kind, _, entry_id = ref.partition(":")
        if kind == "text" and entry_id in item_entries:
            entries.append(item_entries[entry_id])
        if kind == "file" and entry_id in file_entries:
            entries.append(file_entries[entry_id])

    file_bytes = await get_session_file_bytes(sid)
    return {"entries": entries, "file_bytes": file_bytes}


async def get_file_download(sid: str, file_id: str, key: bytes) -> tuple[str, bytes]:
    r = await get_redis()
    raw_meta = await r.hget(_key_files(sid), file_id)
    if not raw_meta:
        raise FileNotFoundError("File not found.")

    meta = _load_meta(raw_meta)
    file_path = _session_dir(sid) / meta["stored_name"]
    if not file_path.exists():
        raise FileNotFoundError("File payload missing.")

    encrypted = file_path.read_bytes()
    data = decrypt_bytes(encrypted, key)
    return meta["name"], data


async def get_item_count(sid: str) -> int:
    r = await get_redis()
    return await r.llen(_key_items(sid))


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


async def get_failed_attempts(sid: str) -> int:
    r = await get_redis()
    val = await r.get(_key_failed(sid))
    return int(val) if val else 0
