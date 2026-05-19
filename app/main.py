"""
main.py — FastAPI application
==============================

Routes:
  GET  /                      → Paste form
  POST /                      → Create session, redirect to /{sid}
  GET  /{sid}                 → Auth form (or session view if cookie valid)
  POST /{sid}/auth            → Verify password, set session cookie
  POST /{sid}/add             → Add item to existing authenticated session
  POST /{sid}/upload          → Upload encrypted file to existing session
  GET  /{sid}/contents        → JSON: fetch text items + file metadata
  GET  /{sid}/files/{file_id} → Download decrypted file payload
  GET  /{sid}/items           → JSON: fetch all decrypted items (AJAX)
  POST /{sid}/wipe            → Delete session immediately
  GET  /{sid}/stream          → SSE: real-time push notifications

Cookie design:
  clip_auth_{sid}  — httponly, secure: proves authentication (value="1")
  clip_pwd_{sid}   — httponly, secure: stores password server-side so JS
                     never needs to know it. Empty string if no password.
"""

import asyncio
from contextlib import asynccontextmanager
from io import BytesIO
from typing import Annotated

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
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import session as sess
import security as sec
from config import (
    APP_VERSION,
    CREATE_RATE_LIMIT_MAX,
    CREATE_RATE_LIMIT_WINDOW_SECONDS,
    DEBUG,
    FILE_MAX_SIZE_BYTES,
    HEALTHZ_WARN_RATIO,
    SESSION_FILE_MAX_BYTES,
    SESSION_TTL_SECONDS,
    SSE_ENABLED,
    TOTAL_FILE_MAX_BYTES,
    UPLOAD_RATE_LIMIT_MAX,
    UPLOAD_RATE_LIMIT_WINDOW_SECONDS,
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

# Trust proxy headers (Passenger/Nginx forward requests as HTTP internally)
# This ensures cookies are set correctly even behind a reverse proxy
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.globals["app_version"] = APP_VERSION
templates.env.globals["sse_enabled"] = SSE_ENABLED


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------

def _auth_cookie(sid: str) -> str:
    return f"clip_auth_{sid}"

def _pwd_cookie(sid: str) -> str:
    return f"clip_pwd_{sid}"


def _set_session_cookies(response: Response, sid: str, password: str) -> None:
    """Set both auth and password cookies — both httponly, secure."""
    common = dict(max_age=SESSION_TTL_SECONDS, httponly=True, secure=True, samesite="strict")
    response.set_cookie(key=_auth_cookie(sid), value="1", **common)
    response.set_cookie(key=_pwd_cookie(sid),  value=password, **common)


def _clear_session_cookies(response: Response, sid: str) -> None:
    response.delete_cookie(key=_auth_cookie(sid))
    response.delete_cookie(key=_pwd_cookie(sid))


def _set_language_cookie(response: Response, lang: str) -> None:
    response.set_cookie(key=LANG_COOKIE, value=lang, max_age=60 * 60 * 24 * 365, samesite="lax")


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


async def _is_authenticated(request: Request, sid: str) -> bool:
    cookie_val = request.cookies.get(_auth_cookie(sid))
    return cookie_val == "1" and await sess.session_exists(sid)


def _get_password(request: Request, sid: str) -> str:
    """Read the stored password from the httponly cookie."""
    return request.cookies.get(_pwd_cookie(sid), "")


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


async def _read_upload_bytes(upload: UploadFile) -> bytes:
    """Read an uploaded file with an explicit per-file size limit."""
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

    if total == 0:
        raise HTTPException(status_code=422, detail="File cannot be empty.")

    return b"".join(chunks)


# ---------------------------------------------------------------------------
# GET /healthz — Liveness + disk budget probe (anonymous)
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
# GET / — Paste form
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return _render_template(request, "index.html", {})


# ---------------------------------------------------------------------------
# POST / — Create session
# ---------------------------------------------------------------------------

@app.post("/")
async def create_session(
    request: Request,
    text: Annotated[str, Form()],
    password: Annotated[str, Form()] = "",
    secure_mode: Annotated[bool, Form()] = False,
):
    ip = get_client_ip(request)

    banned, ban_type = await sec.is_banned(ip)
    if banned:
        raise HTTPException(status_code=429, detail=f"IP {ban_type}-banned.")

    allowed, retry_after = await sec.check_action_quota(
        ip, "create", CREATE_RATE_LIMIT_MAX, CREATE_RATE_LIMIT_WINDOW_SECONDS,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many sessions created from this IP. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    text = text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Text cannot be empty.")
    if len(text) > 500_000:
        raise HTTPException(status_code=413, detail="Text too large (max 500 KB).")
    if len(password) > 50:
        raise HTTPException(status_code=422, detail="Password too long (max 50 chars).")

    sid = await sess.create_session(
        first_item=text,
        password=password,
        secure_mode=secure_mode,
    )

    response = RedirectResponse(url=f"/{sid}", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookies(response, sid, password)
    _set_language_cookie(response, _get_language(request))
    return response


# ---------------------------------------------------------------------------
# GET /{sid} — Session page
# ---------------------------------------------------------------------------

@app.get("/{sid}", response_class=HTMLResponse)
async def session_page(request: Request, sid: str):
    if await sess.session_is_locked(sid):
        return _render_template(request, "locked.html", {"sid": sid}, status_code=410)

    if not await sess.session_exists(sid):
        return _render_template(request, "not_found.html", {"sid": sid}, status_code=404)

    if await _is_authenticated(request, sid):
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
                "uploaded_at",
            )
        }
        lang = _get_language(request)
        upload_limits_text = _tr(
            lang,
            "upload_limits",
            file_max=_human_bytes(FILE_MAX_SIZE_BYTES, lang),
            session_max=_human_bytes(SESSION_FILE_MAX_BYTES, lang),
        )
        return _render_template(
            request,
            "session.html",
            {
                "sid": sid,
                "ttl": SESSION_TTL_SECONDS,
                "file_max_size": FILE_MAX_SIZE_BYTES,
                "session_file_max_bytes": SESSION_FILE_MAX_BYTES,
                "upload_limits_text": upload_limits_text,
                "js_i18n": js_i18n,
            },
        )

    return _render_template(request, "auth.html", {"sid": sid})


# ---------------------------------------------------------------------------
# POST /{sid}/auth — Authenticate
# ---------------------------------------------------------------------------

@app.post("/{sid}/auth")
async def authenticate(
    request: Request,
    sid: str,
    password: Annotated[str, Form()] = "",
):
    ip = get_client_ip(request)

    banned, ban_type = await sec.is_banned(ip)
    if banned:
        raise HTTPException(status_code=429, detail=f"IP {ban_type}-banned.")

    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")

    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session not found.")

    ok = await sess.verify_password(sid, password)

    if not ok:
        if await sess.session_is_locked(sid):
            return JSONResponse(
                {"error": "session_locked"},
                status_code=410,
            )
        banned_now, ban_type = await sec.check_and_record_attempt(ip)
        remaining = await sec.get_attempts_remaining(ip)
        if banned_now:
            return JSONResponse({"error": "ip_banned", "ban_type": ban_type}, status_code=429)
        return JSONResponse({"error": "wrong_password", "attempts_remaining": remaining}, status_code=401)

    await sec.record_success(ip)
    await sess.touch_session(sid)
    response = RedirectResponse(url=f"/{sid}", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookies(response, sid, password)
    _set_language_cookie(response, _get_language(request))
    return response


# ---------------------------------------------------------------------------
# GET /{sid}/items — Fetch decrypted items (authenticated, password from cookie)
# ---------------------------------------------------------------------------

@app.get("/{sid}/items")
async def get_items(request: Request, sid: str):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    password = _get_password(request, sid)
    items = await sess.get_items(sid, password)
    return JSONResponse({"items": items})


@app.get("/{sid}/contents")
async def get_contents(request: Request, sid: str):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    password = _get_password(request, sid)
    contents = await sess.get_session_contents(sid, password)
    return JSONResponse(contents)


# ---------------------------------------------------------------------------
# POST /{sid}/add — Add item (password from cookie)
# ---------------------------------------------------------------------------

@app.post("/{sid}/add")
async def add_item(
    request: Request,
    sid: str,
    text: Annotated[str, Form()],
):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    text = text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Text cannot be empty.")
    if len(text) > 500_000:
        raise HTTPException(status_code=413, detail="Text too large.")

    password = _get_password(request, sid)
    await sess.add_item(sid, text, password)
    return JSONResponse({"ok": True})


@app.post("/{sid}/upload")
async def upload_file(
    request: Request,
    sid: str,
    file: UploadFile = File(...),
):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")
    if not file.filename:
        raise HTTPException(status_code=422, detail="Filename is required.")

    ip = get_client_ip(request)
    allowed, retry_after = await sec.check_action_quota(
        ip, "upload", UPLOAD_RATE_LIMIT_MAX, UPLOAD_RATE_LIMIT_WINDOW_SECONDS,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Upload rate limit exceeded for this IP. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    payload = await _read_upload_bytes(file)
    password = _get_password(request, sid)

    try:
        saved = await sess.save_file(sid, file.filename, payload, password)
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

    return JSONResponse({"ok": True, "file": saved})


@app.get("/{sid}/files/{file_id}")
async def download_file(request: Request, sid: str, file_id: str):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    password = _get_password(request, sid)
    try:
        filename, data = await sess.get_file_download(sid, file_id, password)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="File not found.") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Could not decrypt file.") from exc

    safe_name = filename.replace('"', "")
    return StreamingResponse(
        BytesIO(data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


# ---------------------------------------------------------------------------
# POST /{sid}/wipe — Delete session immediately (authenticated)
# ---------------------------------------------------------------------------

@app.post("/{sid}/wipe")
async def wipe_session(request: Request, sid: str):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")

    await sess.delete_session(sid, wiped=True)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    _clear_session_cookies(response, sid)
    _set_language_cookie(response, _get_language(request))
    return response


# ---------------------------------------------------------------------------
# GET /{sid}/stream — Server-Sent Events (live push, authenticated)
# ---------------------------------------------------------------------------

HEARTBEAT_INTERVAL = 25

@app.get("/{sid}/stream")
async def sse_stream(request: Request, sid: str):
    if not await _is_authenticated(request, sid):
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

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
