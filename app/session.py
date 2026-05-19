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

import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import AsyncIterator, Optional

import redis.asyncio as aioredis

from config import (
    FILE_MAX_SIZE_BYTES,
    REDIS_URL,
    SESSION_FILE_MAX_BYTES,
    SESSION_MAX_FAILED_ATTEMPTS,
    SESSION_TTL_SECONDS,
    UPLOAD_ROOT,
)
from crypto import decrypt, decrypt_bytes, encrypt, encrypt_bytes, generate_session_id


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


def _make_text_meta(item_id: str, size: int) -> dict:
    return {"id": item_id, "size": size, "created_at": _now()}


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
    password: str,
) -> dict:
    token = encrypt(plaintext, sid, password)
    item_id = uuid.uuid4().hex
    meta = _make_text_meta(item_id, len(plaintext.encode("utf-8")))

    async with r.pipeline(transaction=True) as pipe:
        pipe.rpush(_key_items(sid), token)
        pipe.hset(_key_item_meta(sid), item_id, json.dumps(meta))
        pipe.rpush(_key_item_order(sid), item_id)
        pipe.rpush(_key_entries(sid), _entry_ref("text", item_id))
        await pipe.execute()

    return meta


async def create_session(
    first_item: str,
    password: str,
    secure_mode: bool = False,
) -> str:
    r = await get_redis()
    cleanup_expired_upload_dirs()

    for _ in range(5):
        sid = generate_session_id(secure_mode=secure_mode)
        meta = {
            "has_password": "1" if password else "0",
            "created_at": str(_now()),
        }

        async with r.pipeline(transaction=True) as pipe:
            pipe.hsetnx(_key_meta(sid), "has_password", meta["has_password"])
            pipe.hsetnx(_key_meta(sid), "created_at", meta["created_at"])
            results = await pipe.execute()

        if not results[0]:
            continue

        await _append_text_entry(r, sid, first_item, password)
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


async def verify_password(sid: str, password: str) -> bool:
    r = await get_redis()

    if await session_is_locked(sid):
        return False

    has_pwd = await session_has_password(sid)
    if not has_pwd:
        if password != "":
            failures = await r.incr(_key_failed(sid))
            await r.expire(_key_failed(sid), SESSION_TTL_SECONDS)
            if failures >= SESSION_MAX_FAILED_ATTEMPTS:
                await lock_session_forever(sid)
            return False
        return True

    first_token = await r.lindex(_key_items(sid), 0)
    if not first_token:
        return False

    try:
        decrypt(first_token, sid, password)
        await r.delete(_key_failed(sid))
        return True
    except Exception:
        failures = await r.incr(_key_failed(sid))
        await r.expire(_key_failed(sid), SESSION_TTL_SECONDS)
        if failures >= SESSION_MAX_FAILED_ATTEMPTS:
            await lock_session_forever(sid)
        return False


async def add_item(sid: str, plaintext: str, password: str) -> None:
    r = await get_redis()
    await _append_text_entry(r, sid, plaintext, password)
    await _refresh_ttl(r, sid)
    await r.publish(_channel(sid), "new_item")


async def touch_session(sid: str) -> None:
    r = await get_redis()
    if await r.exists(_key_meta(sid)):
        await _refresh_ttl(r, sid)


async def get_items(sid: str, password: str) -> list[str]:
    r = await get_redis()
    tokens = await r.lrange(_key_items(sid), 0, -1)
    results = []
    for token in tokens:
        try:
            results.append(decrypt(token, sid, password))
        except Exception:
            pass
    return results


async def save_file(sid: str, filename: str, data: bytes, password: str) -> dict:
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

    file_id = uuid.uuid4().hex
    encrypted = encrypt_bytes(data, sid, password)
    session_dir = _session_dir(sid)
    session_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{file_id}.bin"
    file_path = session_dir / stored_name
    with file_path.open("wb") as handle:
        handle.write(encrypted)

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


async def get_session_contents(sid: str, password: str) -> dict:
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
            text = decrypt(token, sid, password)
        except Exception:
            continue
        meta = _load_meta(meta_raw)
        item_entries[item_id] = {
            "id": item_id,
            "type": "text",
            "text": text,
            "size": meta["size"],
            "created_at": meta["created_at"],
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


async def get_file_download(sid: str, file_id: str, password: str) -> tuple[str, bytes]:
    r = await get_redis()
    raw_meta = await r.hget(_key_files(sid), file_id)
    if not raw_meta:
        raise FileNotFoundError("File not found.")

    meta = _load_meta(raw_meta)
    file_path = _session_dir(sid) / meta["stored_name"]
    if not file_path.exists():
        raise FileNotFoundError("File payload missing.")

    encrypted = file_path.read_bytes()
    data = decrypt_bytes(encrypted, sid, password)
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
