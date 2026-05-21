"""
main.py — FastAPI application (E2EE / anon mode, v2).
=======================================================

Routes:
  GET  /                            → Paste form (loads JS crypto bundle)
  POST /                            → Create session from client ciphertext
  GET  /{sid}                       → Session page or auth handshake
  GET  /{sid}/verifier               → Encrypted verifier blob + has_password
  POST /{sid}/auth                  → Verify auth_proof, issue signed token
  GET  /{sid}/contents              → JSON: ciphertext blobs + opaque metadata
  POST /{sid}/items                 → Add a ciphertext text item
  POST /{sid}/upload                → Upload encrypted file + optional thumb
  GET  /{sid}/files/{file_id}       → Encrypted file bytes (header: enc name)
  GET  /{sid}/files/{file_id}/thumb → Encrypted thumb bytes
  POST /{sid}/items/{item_id}/delete
  POST /{sid}/files/{file_id}/delete
  POST /{sid}/wipe                  → Delete session immediately
  GET  /{sid}/stream                → SSE for live updates
  GET  /pow/challenge               → Issue a PoW challenge
  GET  /healthz                     → Liveness probe (anonymous)

Cookies:
  clip_token_{sid}  — httponly, secure, samesite=strict: HMAC-signed write
                      token (see tokens.py). Issued after a successful auth
                      handshake (client proves it could decrypt the verifier).
                      Lifetime = session TTL, sliding on each authenticated
                      response. Contains NO key material.

There are no IP-based controls. Anti-abuse on anonymous endpoints (POST /,
POST /{sid}/auth) is via proof-of-work. Per-token write quotas cap how
much a single browser session can spam.
"""

import asyncio
import base64
import hashlib
import re
import time
from contextlib import asynccontextmanager
from io import BytesIO
from pathlib import Path
from typing import Annotated, Optional

from fastapi import (
    File,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import pow as pow_mod
import security as sec
import session as sess
import tokens as tok
from config import (
    APP_BUILD_ID,
    APP_COMMIT,
    APP_VERSION,
    CLI_DOWNLOAD_URL_TEMPLATE,
    CLI_INSTALL_SCRIPT_PS1_URL,
    CLI_INSTALL_SCRIPT_URL,
    CLI_PLATFORMS,
    CLI_REPO_URL,
    DEBUG,
    FILE_MAX_SIZE_BYTES,
    HEALTHZ_WARN_RATIO,
    POW_CHALLENGE_TTL_SECONDS,
    POW_DIFFICULTY_BITS,
    SESSION_FILE_MAX_BYTES,
    SESSION_TTL_SECONDS,
    SSE_ENABLED,
    TOTAL_FILE_MAX_BYTES,
)
from i18n import DEFAULT_LANGUAGE, LANG_COOKIE, SUPPORTED_LANGUAGES, get_translations, normalize_language


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = asyncio.create_task(sess.periodic_cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        await sess.close_redis()


app = FastAPI(lifespan=lifespan, docs_url="/docs" if DEBUG else None)

# Proxy headers still trusted so secure-cookie scheme detection works behind
# Caddy. We never read the client IP from them — there is no IP tracking.
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ---------------------------------------------------------------------------
# Subresource Integrity (SRI) hashes
# ---------------------------------------------------------------------------
# Computed once at startup from the files actually on disk inside the
# container. Means base.html declares an integrity= attribute on each
# crypto script tag, and the browser refuses to execute if a CDN or proxy
# silently swapped the file mid-flight. Doesn't protect against the
# operator swapping both the script AND the index page in lockstep, but
# closes the partial-compromise window.

_STATIC = Path("static")


def _sri_sha384(path: Path) -> str:
    digest = hashlib.sha384(path.read_bytes()).digest()
    return "sha384-" + base64.b64encode(digest).decode("ascii")


SRI_HASHES = {
    "hash_wasm":     _sri_sha384(_STATIC / "js" / "vendor" / "hash-wasm.umd.min.js"),
    "clip_crypto":   _sri_sha384(_STATIC / "js" / "clip-crypto.js"),
    "clip_keystore": _sri_sha384(_STATIC / "js" / "clip-keystore.js"),
}


templates.env.globals["app_version"]   = APP_VERSION
templates.env.globals["app_commit"]    = APP_COMMIT
templates.env.globals["app_build_id"]  = APP_BUILD_ID
templates.env.globals["sse_enabled"]   = SSE_ENABLED
templates.env.globals["pow_difficulty"] = POW_DIFFICULTY_BITS
templates.env.globals["sri"]           = SRI_HASHES


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------

def _token_cookie(sid: str) -> str:
    return f"clip_token_{sid}"


def _set_token_cookie(response: Response, sid: str, ttl: int = SESSION_TTL_SECONDS) -> None:
    response.set_cookie(
        key=_token_cookie(sid),
        value=tok.issue(sid, ttl_seconds=ttl),
        max_age=ttl,
        httponly=True,
        secure=True,
        samesite="strict",
    )


def _clear_token_cookie(response: Response, sid: str) -> None:
    response.delete_cookie(key=_token_cookie(sid))


async def _refresh_token_cookie(response: Response, request: Request, sid: str) -> None:
    """Slide the signed-token cookie's lifetime to match the server TTL."""
    expires_at = await sess.get_session_expires_at(sid)
    if not expires_at:
        return
    remaining = expires_at - int(time.time())
    if remaining <= 0:
        return
    if not request.cookies.get(_token_cookie(sid)):
        return
    _set_token_cookie(response, sid, ttl=remaining)


def _set_language_cookie(response: Response, lang: str) -> None:
    response.set_cookie(key=LANG_COOKIE, value=lang, max_age=60 * 60 * 24 * 365, samesite="lax")


def _has_valid_token(request: Request, sid: str) -> bool:
    token = request.cookies.get(_token_cookie(sid), "")
    return tok.verify(token, sid) is not None


def _get_language(request: Request) -> str:
    query_lang = request.query_params.get("lang")
    if query_lang:
        return normalize_language(query_lang)

    cookie_lang = request.cookies.get(LANG_COOKIE)
    if cookie_lang:
        return normalize_language(cookie_lang)

    accept_language = request.headers.get("Accept-Language", "")
    if accept_language:
        first = accept_language.split(",", 1)[0]
        return normalize_language(first)

    return DEFAULT_LANGUAGE


def _tr(lang: str, key: str, **kwargs) -> str:
    value = get_translations(lang)[key]
    return value.format(**kwargs) if kwargs else value


def _human_bytes(n: int, lang: str = "en") -> str:
    mb, gb = ("Mo", "Go") if lang == "fr" else ("MB", "GB")
    if n >= 1024**3 and n % (1024**3) == 0:
        return f"{n // (1024**3)} {gb}"
    return f"{n // (1024**2)} {mb}"


def _render_template(request: Request, template_name: str, context: dict, status_code: int = 200):
    lang = _get_language(request)
    tr = get_translations(lang)
    template_context = {
        "request": request,
        "lang": lang,
        "tr": tr,
        "supported_languages": SUPPORTED_LANGUAGES,
        **context,
    }
    response = templates.TemplateResponse(template_name, template_context, status_code=status_code)
    if request.cookies.get(LANG_COOKIE) != lang or request.query_params.get("lang"):
        _set_language_cookie(response, lang)
    return response


async def _enforce_pow(challenge: str, nonce: str) -> None:
    ok = await pow_mod.consume(challenge, nonce, POW_DIFFICULTY_BITS)
    if not ok:
        raise HTTPException(status_code=429, detail="Invalid or expired proof-of-work.")


async def _enforce_write_quota(token: str) -> None:
    allowed, retry_after = await sec.check_write_quota(token)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Write rate limit exceeded.",
            headers={"Retry-After": str(retry_after)},
        )


async def _read_upload_bytes(upload: UploadFile, *, allow_empty: bool = False) -> bytes:
    """Stream-read an UploadFile with a per-file size cap."""
    total = 0
    chunks = []
    try:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > FILE_MAX_SIZE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large (max {FILE_MAX_SIZE_BYTES // (1024 * 1024)} MB).",
                )
            chunks.append(chunk)
    finally:
        await upload.close()

    if total == 0 and not allow_empty:
        raise HTTPException(status_code=422, detail="File cannot be empty.")

    return b"".join(chunks)


# ---------------------------------------------------------------------------
# PWA: service worker + manifest
# ---------------------------------------------------------------------------
# The service worker must be served from the origin root for its default
# scope to cover the whole site. Mounting it under /static would limit it
# to /static/* which is useless for HTML caching/install. The explicit
# Service-Worker-Allowed header is required because the script *lives* at
# /static/sw.js on disk but the registered URL is /sw.js — without the
# header browsers reject scope expansion to "/".

@app.get("/sw.js")
async def service_worker():
    return FileResponse(
        "static/sw.js",
        media_type="application/javascript",
        headers={
            "Cache-Control": "no-cache",  # Always re-fetch — registration query string busts the cache
            "Service-Worker-Allowed": "/",
        },
    )


@app.get("/manifest.webmanifest")
async def manifest():
    return FileResponse(
        "static/manifest.json",
        media_type="application/manifest+json",
        headers={"Cache-Control": "public, max-age=3600"},
    )


# ---------------------------------------------------------------------------
# GET /healthz
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    used = sess.global_used_bytes()
    cap = TOTAL_FILE_MAX_BYTES
    ratio = used / cap if cap > 0 else 0.0

    redis_ok = True
    try:
        r = await sess.get_redis()
        await r.ping()
    except Exception:
        redis_ok = False

    reasons = []
    if not redis_ok:
        reasons.append("redis_unreachable")
    if ratio >= HEALTHZ_WARN_RATIO:
        reasons.append("disk_over_threshold")

    healthy = not reasons
    payload = {
        "status": "ok" if healthy else "warn",
        "reasons": reasons,
        "redis_ok": redis_ok,
        "disk_used_bytes": used,
        "disk_cap_bytes": cap,
        "disk_ratio": round(ratio, 4),
        "warn_ratio": HEALTHZ_WARN_RATIO,
        "version": APP_VERSION,
    }
    return JSONResponse(payload, status_code=200 if healthy else 503)


# ---------------------------------------------------------------------------
# CLI distribution — discovery page, install-script redirect, binary redirect
# ---------------------------------------------------------------------------
# All three routes are declared BEFORE the catch-all GET /{sid} below, so the
# literal "/cli" and "/install.sh" paths take precedence over session lookup.
# /cli/{platform} has two segments and would never collide, but it lives in
# the same cluster for cohesion.

_CLI_PLATFORM_RE = re.compile(r"^[a-z0-9._-]{1,40}$")


@app.get("/cli", response_class=HTMLResponse)
async def cli_page(request: Request):
    return _render_template(
        request,
        "cli.html",
        {
            "base_url": str(request.base_url).rstrip("/"),
            "platforms": CLI_PLATFORMS,
            "cli_repo_url": CLI_REPO_URL,
        },
    )


@app.get("/install.sh")
async def install_script_redirect():
    return RedirectResponse(
        url=CLI_INSTALL_SCRIPT_URL,
        status_code=status.HTTP_302_FOUND,
    )


@app.get("/install.ps1")
async def install_script_ps1_redirect():
    return RedirectResponse(
        url=CLI_INSTALL_SCRIPT_PS1_URL,
        status_code=status.HTTP_302_FOUND,
    )


@app.get("/cli/{platform}")
async def cli_download(platform: str):
    if not _CLI_PLATFORM_RE.match(platform):
        raise HTTPException(status_code=404, detail="Unknown platform.")
    return RedirectResponse(
        url=CLI_DOWNLOAD_URL_TEMPLATE.format(platform=platform),
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------------------------
# GET /pow/challenge — Public PoW challenge issuance
# ---------------------------------------------------------------------------

@app.get("/pow/challenge")
async def pow_challenge():
    challenge, difficulty = await pow_mod.issue_challenge(
        POW_DIFFICULTY_BITS, ttl_seconds=POW_CHALLENGE_TTL_SECONDS
    )
    return JSONResponse({"challenge": challenge, "difficulty": difficulty})


# ---------------------------------------------------------------------------
# GET / — Paste form
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return _render_template(request, "index.html", {})


# ---------------------------------------------------------------------------
# POST / — Create session (E2EE)
# ---------------------------------------------------------------------------

@app.post("/")
async def create_session(
    request: Request,
    first_item_ct: Annotated[str, Form()],
    first_item_size: Annotated[int, Form()],
    has_password: Annotated[bool, Form()],
    salt: Annotated[str, Form()],
    verifier_blob: Annotated[str, Form()],
    auth_anchor: Annotated[str, Form()],
    pow_challenge: Annotated[str, Form()],
    pow_nonce: Annotated[str, Form()],
    secure_mode: Annotated[bool, Form()] = False,
    secret: Annotated[bool, Form()] = False,
):
    await _enforce_pow(pow_challenge, pow_nonce)

    if not first_item_ct or first_item_size <= 0:
        raise HTTPException(status_code=422, detail="First item is required.")
    if first_item_size > 500_000:
        raise HTTPException(status_code=413, detail="Text too large (max 500 KB).")
    if not verifier_blob or not auth_anchor or not salt:
        raise HTTPException(status_code=422, detail="Auth payload missing.")
    # auth_anchor is a sha256 hex digest: 64 hex chars.
    if len(auth_anchor) != 64 or not all(c in "0123456789abcdef" for c in auth_anchor):
        raise HTTPException(status_code=422, detail="Malformed auth anchor.")
    # salt is client-generated random base64. Reject obviously bogus lengths.
    if len(salt) < 16 or len(salt) > 64:
        raise HTTPException(status_code=422, detail="Malformed salt.")

    sid = await sess.create_session(
        first_item_ct=first_item_ct,
        first_item_size=int(first_item_size),
        has_password=has_password,
        salt=salt,
        verifier_blob=verifier_blob,
        auth_anchor=auth_anchor,
        secure_mode=secure_mode,
        secret=secret,
    )

    # JSON instead of redirect: the client needs to stash the derived key in
    # sessionStorage under the freshly returned sid before navigating.
    response = JSONResponse({"ok": True, "sid": sid, "redirect": f"/{sid}"})
    _set_token_cookie(response, sid)
    _set_language_cookie(response, _get_language(request))
    return response


# ---------------------------------------------------------------------------
# GET /{sid} — Session page or auth handshake
# ---------------------------------------------------------------------------

@app.get("/{sid}", response_class=HTMLResponse)
async def session_page(request: Request, sid: str):
    if await sess.session_is_locked(sid):
        return _render_template(request, "locked.html", {"sid": sid}, status_code=410)

    if not await sess.session_exists(sid):
        return _render_template(request, "not_found.html", {"sid": sid}, status_code=404)

    # ?reauth=1 forces the auth handshake even when the token cookie is valid.
    # Used by the client when sessionStorage lost the key (tab was closed and
    # reopened) but the cookie is still there — derive again before reading.
    force_reauth = request.query_params.get("reauth") == "1"

    if _has_valid_token(request, sid) and not force_reauth:
        js_i18n = {
            key: _tr(_get_language(request), key)
            for key in (
                "copy",
                "copied",
                "download",
                "loading",
                "timeline_empty",
                "empty_state_feed",
                "saving",
                "added",
                "error",
                "select_at_least_one_file",
                "upload_complete",
                "session_locked_feed",
                "session_wiped_feed",
                "session_expired_feed",
                "live",
                "reconnecting",
                "session_ended",
                "status_used",
                "item_label",
                "file_label",
                "delete",
                "deleting",
                "delete_item_title",
                "delete_file_title",
                "delete_aria_item",
                "delete_aria_file",
                "reveal",
                "hide",
            )
        }
        lang = _get_language(request)
        upload_limits_text = _tr(
            lang,
            "upload_limits",
            file_max=_human_bytes(FILE_MAX_SIZE_BYTES, lang),
            session_max=_human_bytes(SESSION_FILE_MAX_BYTES, lang),
        )
        expires_at = await sess.get_session_expires_at(sid)
        response = _render_template(
            request,
            "session.html",
            {
                "sid": sid,
                "ttl": SESSION_TTL_SECONDS,
                "expires_at": expires_at or 0,
                "file_max_size": FILE_MAX_SIZE_BYTES,
                "session_file_max_bytes": SESSION_FILE_MAX_BYTES,
                "upload_limits_text": upload_limits_text,
                "js_i18n": js_i18n,
            },
        )
        await _refresh_token_cookie(response, request, sid)
        return response

    has_password = await sess.session_has_password(sid)
    return _render_template(request, "auth.html", {"sid": sid, "has_password": has_password})


# ---------------------------------------------------------------------------
# GET /{sid}/verifier — Public: ciphertext verifier blob for client handshake
# ---------------------------------------------------------------------------

@app.get("/{sid}/verifier")
async def get_verifier(sid: str):
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session not found.")
    blob = await sess.get_verifier_blob(sid)
    salt = await sess.get_salt(sid)
    if not blob or not salt:
        raise HTTPException(status_code=404, detail="No verifier stored.")
    has_password = await sess.session_has_password(sid)
    return JSONResponse({"verifier": blob, "salt": salt, "has_password": has_password})


# ---------------------------------------------------------------------------
# POST /{sid}/auth — Verify auth_proof, issue signed token
# ---------------------------------------------------------------------------

@app.post("/{sid}/auth")
async def authenticate(
    request: Request,
    sid: str,
    auth_proof: Annotated[str, Form()],
    pow_challenge: Annotated[str, Form()],
    pow_nonce: Annotated[str, Form()],
):
    await _enforce_pow(pow_challenge, pow_nonce)

    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")

    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session not found.")

    if await sess.verify_auth_proof(sid, auth_proof):
        await sec.clear_failed_auth(sid)
        response = JSONResponse({"ok": True, "redirect": f"/{sid}"})
        _set_token_cookie(response, sid)
        _set_language_cookie(response, _get_language(request))
        return response

    failures = await sec.record_failed_auth(sid)
    if await sec.session_should_lock(sid):
        await sess.lock_session_forever(sid)
        return JSONResponse({"error": "session_locked"}, status_code=410)
    return JSONResponse({"error": "wrong_password", "failures": failures}, status_code=401)


# ---------------------------------------------------------------------------
# GET /{sid}/contents — All ciphertext blobs (authenticated)
# ---------------------------------------------------------------------------

@app.get("/{sid}/contents")
async def get_contents(request: Request, sid: str):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    contents = await sess.get_session_contents(sid)
    response = JSONResponse(contents)
    await _refresh_token_cookie(response, request, sid)
    return response


# ---------------------------------------------------------------------------
# POST /{sid}/items — Add ciphertext item
# ---------------------------------------------------------------------------

@app.post("/{sid}/items")
async def add_item(
    request: Request,
    sid: str,
    ciphertext: Annotated[str, Form()],
    plain_size: Annotated[int, Form()],
    secret: Annotated[bool, Form()] = False,
):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    await _enforce_write_quota(request.cookies.get(_token_cookie(sid), ""))

    if not ciphertext or plain_size <= 0:
        raise HTTPException(status_code=422, detail="Ciphertext is required.")
    if plain_size > 500_000:
        raise HTTPException(status_code=413, detail="Text too large.")

    await sess.add_item(sid, ciphertext, int(plain_size), secret=secret)
    response = JSONResponse({"ok": True})
    await _refresh_token_cookie(response, request, sid)
    return response


# ---------------------------------------------------------------------------
# POST /{sid}/upload — Encrypted file upload
# ---------------------------------------------------------------------------

@app.post("/{sid}/upload")
async def upload_file(
    request: Request,
    sid: str,
    encrypted_name: Annotated[str, Form()],
    plain_size: Annotated[int, Form()],
    file: UploadFile = File(...),
    thumb: Optional[UploadFile] = File(None),
):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    await _enforce_write_quota(request.cookies.get(_token_cookie(sid), ""))

    if not encrypted_name:
        raise HTTPException(status_code=422, detail="Encrypted name is required.")

    payload = await _read_upload_bytes(file)
    thumb_payload: Optional[bytes] = None
    if thumb is not None:
        thumb_payload = await _read_upload_bytes(thumb, allow_empty=True) or None

    try:
        saved = await sess.save_file(
            sid,
            encrypted_name=encrypted_name,
            plain_size=int(plain_size),
            ciphertext=payload,
            thumb_ciphertext=thumb_payload,
        )
    except ValueError as exc:
        message = str(exc)
        if message == "File too large.":
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {_human_bytes(FILE_MAX_SIZE_BYTES)}).",
            ) from exc
        if message == "Session file quota exceeded.":
            raise HTTPException(
                status_code=413,
                detail=f"Session quota exceeded (max {_human_bytes(SESSION_FILE_MAX_BYTES)}).",
            ) from exc
        if message == "Service quota exceeded.":
            raise HTTPException(
                status_code=503,
                detail="Service temporarily at capacity. Try again later.",
                headers={"Retry-After": "300"},
            ) from exc
        if message == "Disk full.":
            raise HTTPException(
                status_code=507,
                detail="Server storage exhausted. Try again later.",
            ) from exc
        raise HTTPException(status_code=422, detail=message) from exc

    response = JSONResponse({"ok": True, "file": saved})
    await _refresh_token_cookie(response, request, sid)
    return response


# ---------------------------------------------------------------------------
# GET /{sid}/files/{file_id} — Ciphertext file body (binary)
# ---------------------------------------------------------------------------

@app.get("/{sid}/files/{file_id}")
async def download_file(request: Request, sid: str, file_id: str):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    try:
        encrypted_name, ciphertext = await sess.get_file_ciphertext(sid, file_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="File not found.") from exc

    # The encrypted_name is itself an AES-GCM token (base64-safe ASCII), so
    # putting it in a custom response header is fine — but to keep the wire
    # format trivial we URL-encode it just in case.
    safe_name_header = base64.urlsafe_b64encode(encrypted_name.encode("utf-8")).decode("ascii")
    response = StreamingResponse(
        BytesIO(ciphertext),
        media_type="application/octet-stream",
        headers={
            "X-Clip-Encrypted-Name": safe_name_header,
            "Cache-Control": "private, no-store",
        },
    )
    await _refresh_token_cookie(response, request, sid)
    return response


# ---------------------------------------------------------------------------
# GET /{sid}/files/{file_id}/thumb — Ciphertext thumbnail bytes
# ---------------------------------------------------------------------------

@app.get("/{sid}/files/{file_id}/thumb")
async def download_thumb(request: Request, sid: str, file_id: str):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    try:
        data = await sess.get_thumb_ciphertext(sid, file_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="File not found.") from exc

    if data is None:
        raise HTTPException(status_code=404, detail="No thumbnail.")

    response = StreamingResponse(
        BytesIO(data),
        media_type="application/octet-stream",
        headers={"Cache-Control": "private, no-store"},
    )
    await _refresh_token_cookie(response, request, sid)
    return response


# ---------------------------------------------------------------------------
# POST /{sid}/items/{item_id}/delete
# ---------------------------------------------------------------------------

@app.post("/{sid}/items/{item_id}/delete")
async def delete_item_endpoint(request: Request, sid: str, item_id: str):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    deleted = await sess.delete_item(sid, item_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Item not found.")

    response = JSONResponse({"ok": True})
    await _refresh_token_cookie(response, request, sid)
    return response


# ---------------------------------------------------------------------------
# POST /{sid}/files/{file_id}/delete
# ---------------------------------------------------------------------------

@app.post("/{sid}/files/{file_id}/delete")
async def delete_file_endpoint(request: Request, sid: str, file_id: str):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    deleted = await sess.delete_file(sid, file_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="File not found.")

    response = JSONResponse({"ok": True})
    await _refresh_token_cookie(response, request, sid)
    return response


# ---------------------------------------------------------------------------
# POST /{sid}/wipe
# ---------------------------------------------------------------------------

@app.post("/{sid}/wipe")
async def wipe_session(request: Request, sid: str):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")

    await sess.delete_session(sid, wiped=True)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    _clear_token_cookie(response, sid)
    _set_language_cookie(response, _get_language(request))
    return response


# ---------------------------------------------------------------------------
# GET /{sid}/stream — SSE
# ---------------------------------------------------------------------------

HEARTBEAT_INTERVAL = 25

@app.get("/{sid}/stream")
async def sse_stream(request: Request, sid: str):
    if not _has_valid_token(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")

    async def event_generator():
        yield "data: connected\n\n"

        subscriber = sess.subscribe_to_session(sid)
        queue: asyncio.Queue = asyncio.Queue()

        async def _listen():
            async for event in subscriber:
                await queue.put(event)
            await queue.put(None)

        listener_task = asyncio.create_task(_listen())

        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)
                except asyncio.TimeoutError:
                    if not await sess.session_exists(sid):
                        yield "data: session_expired\n\n"
                        break
                    if await sess.session_is_locked(sid):
                        yield "data: session_locked\n\n"
                        break
                    yield "data: heartbeat\n\n"
                    continue

                if event is None:
                    break

                yield f"data: {event}\n\n"

                if event in ("session_expired", "session_locked", "session_wiped"):
                    break

                if await request.is_disconnected():
                    break

        finally:
            listener_task.cancel()
            try:
                await listener_task
            except asyncio.CancelledError:
                pass

    response = StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
    await _refresh_token_cookie(response, request, sid)
    return response
