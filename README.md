# Online Clipboard

Secure, ephemeral clipboard and file sharing between machines that cannot communicate directly.  
Designed for RDP sessions where clipboard sync is disabled, or any scenario requiring
a quick, passwordless (or password-protected) data transfer between two browsers.

---

## How it works

1. **Paste** your data on Machine A, optionally set a password, create a session
2. **Upload** encrypted files from the session page if needed
3. **Share** the session URL with Machine B
4. **Retrieve** text and files within 2 hours
5. **Everything is wiped automatically** — no traces left after 2 hours of inactivity

Sessions can also be wiped manually at any time via the "Wipe session" button.

The UI is available in **English and French** (auto-detected from `Accept-Language`, switchable via the language toggle in the header).
A **QR-code button** next to the session URL opens a scannable modal — handy for handing off a session from a desktop to a phone without typing the link.

---

## Per-message and per-file controls

- **Secret mode** — opt-in per text item, toggled next to the message input.
  Masks both typing (`-webkit-text-security: disc`, Chromium-based browsers
  only) and the rendered card (`••••••`) with a one-click reveal. The
  content is still encrypted at rest like everything else; secret mode is
  shoulder-surfing protection, not additional cryptography.
- **Individual delete** — each text item and each file has a trash button.
  Removes only that entry; the rest of the session continues. Files also
  remove their on-disk encrypted blob and any thumbnail.
- **Inline previews** — at upload time the server generates a thumbnail
  (JPEG, 240px max bound) for supported formats and stores it encrypted
  alongside the file:
  - **Images**: jpg, jpeg, png, gif, webp, bmp, tif, tiff, ico
  - **PDF**: first page rendered via PyMuPDF
  - **Text and code**: txt, md, csv, json, yaml, toml, html, css, js, ts,
    py, rs, go, sh, sql, … plus a UTF-8 + low control-char content sniff
    for files without (or with misleading) extensions. The first ~16 lines
    are drawn onto a 320×240 canvas in DejaVu Sans Mono.
  Office formats (Word / Excel / PowerPoint) intentionally not covered —
  they require shipping LibreOffice in the container (~400 MB image).
  Thumbnail fetch goes through `/{sid}/files/{id}/thumb` and inherits the
  same auth gate as the file download.
- **Header modals** — an info button opens the *About* card (app version,
  source link), and a cookie button opens the *Privacy & cookies* card
  detailing every cookie, what's encrypted, the trust boundaries, and the
  retention window.

---

## Security model

| Layer | Mechanism |
|---|---|
| Encryption | AES-256-GCM (authenticated — detects tampering) |
| Key derivation | Argon2id — password + server secret → 256-bit key |
| Server pepper | `CLIPBOARD_SERVER_SECRET` — Redis dump useless without it |
| Transport | HTTPS only (HSTS enforced by your reverse proxy) |
| Session TTL | 2-hour sliding window, reset only on real activity (not heartbeats) |
| Auth brute-force | IP rate limiting on bad passwords → temp ban → permanent ban |
| Anti-bot | Per-IP quotas on session creation and file upload (429 + `Retry-After`) |
| Session lockdown | Auto-lock after too many failed attempts, data wiped immediately |
| No plaintext | Data never stored unencrypted; user password never written anywhere — only the Argon2id-derived key is held, in an `httponly` cookie |
| File storage | Encrypted files stored ephemerally on disk, deleted with the session |

### Password handling

The user-typed password is never persisted anywhere — not in Redis, not on disk, not
even in a cookie. At session creation and at auth verification, the server derives a
32-byte AES key via `Argon2id(password, salt=session_id, pepper=CLIPBOARD_SERVER_SECRET)`
and stores the **derived key** (base64) in an `httponly`, `secure`, `samesite=strict`
cookie named `clip_key_<sid>`. Subsequent requests use that key directly for AES-GCM
encrypt/decrypt — Argon2id runs once per auth, not once per request.

Whether a session has a password or not is never revealed to unauthenticated visitors.
Submitting a non-empty password on a passwordless session is treated as a wrong password.

### Trust boundaries

What at-rest encryption protects against:

- Redis dump theft, disk leak, server backups — useless without the derived key.
  Even if an attacker also extracts the pepper, they still need to brute-force the
  password through Argon2id, which is intentionally slow.
- Page-level XSS — the derived key sits in an `httponly` cookie, so an injected
  script cannot read it via `document.cookie`.
- CSRF — `samesite=strict` keeps the cookie out of cross-site requests.
- Password reuse leakage — the cookie holds the derived key, not the user-typed
  password. Whoever reads the cookie can decrypt this session but cannot recover
  the password for use elsewhere.

What it does **not** protect against:

- A malicious or compromised operator. The derived key rides in the cookie on every
  request, and the server holds the pepper. Anyone with code execution on the live
  server can decrypt active sessions.
- Anything with access to the user's cookie store: certain browser devtools modes
  that surface `httponly` cookies, malware running under the user account, the device
  owner themselves. They get the derived key — same effect as having the password
  for this session.
- The session URL itself. Whoever has it can attempt to authenticate; the password
  (if set) is the only barrier from that point.

### Session IDs

- **Normal mode**: 5 characters (~916 million combinations)
- **Secure mode**: 50 characters (brute-force proof)

---

## Quick start

### 1. Generate your server secret

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — paste your generated secret into CLIPBOARD_SERVER_SECRET
```

### 3. Run

```bash
docker compose up -d
```

App available at `http://localhost:8000` (bound to loopback by the
default `docker-compose.yml`). Put a reverse proxy of your choice in
front for TLS — sample Nginx config in `nginx.conf`, but Caddy,
Traefik, or anything else works as well.

---

## Production deployment

Any reverse proxy that can terminate TLS and forward to
`127.0.0.1:8000` works. The app trusts standard proxy headers
(`X-Forwarded-For`, etc.) via FastAPI's `ProxyHeadersMiddleware`.

### Sample: Nginx + Let's Encrypt

```bash
certbot certonly --nginx -d your.domain.com
cp nginx.conf /etc/nginx/sites-available/clipboard
# Edit: replace 'your.domain.com' with your actual domain
ln -s /etc/nginx/sites-available/clipboard /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### Sample: Caddy

```caddy
clipboard.your.domain {
    reverse_proxy 127.0.0.1:8000
}
```

---

## Project structure

```
├── app/
│   ├── main.py         # FastAPI routes (incl. /healthz)
│   ├── crypto.py       # AES-256-GCM encryption + Argon2id KDF
│   ├── session.py      # Redis session mgmt, pub/sub, periodic sweeper
│   ├── security.py     # IP rate limiting (auth + per-action quotas)
│   ├── config.py       # Environment configuration
│   ├── i18n.py         # EN/FR translations
│   ├── static/         # Static assets (incl. vendored qrcode-generator)
│   └── templates/
│       ├── base.html       # Base layout + styles + lang switch
│       ├── index.html      # Session creation form + mobile info modal
│       ├── auth.html       # Authentication form
│       ├── session.html    # Active session view
│       ├── locked.html     # Locked session page
│       └── not_found.html  # Expired/unknown session page
├── tests/
│   ├── conftest.py
│   └── test_crypto.py  # Crypto unit tests
├── Dockerfile
├── docker-compose.yml
├── nginx.conf          # Sample Nginx config (optional)
├── .env.example
└── README.md
```

---

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `CLIPBOARD_SERVER_SECRET` | **required** | 64-char hex server pepper — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `SESSION_TTL_SECONDS` | `7200` | Session lifetime in seconds (2 hours) |
| `FILE_MAX_SIZE_BYTES` | `104857600` | Max single-file size — 100 MiB |
| `SESSION_FILE_MAX_BYTES` | `1073741824` | Max total file payload per session — 1 GiB |
| `TOTAL_FILE_MAX_BYTES` | `10737418240` | Global disk budget across all sessions — 10 GiB |
| `CLEANUP_INTERVAL_SECONDS` | `600` | How often the background task purges expired session dirs from disk |
| `UPLOAD_ROOT` | `/tmp/online_clipboard_uploads` | Ephemeral encrypted file storage directory |
| `HEALTHZ_WARN_RATIO` | `0.8` | `/healthz` returns 503 when `disk_used / TOTAL_FILE_MAX_BYTES` reaches this ratio |
| `RATE_LIMIT_MAX_ATTEMPTS` | `10` | Failed auth attempts before temp ban |
| `RATE_LIMIT_WINDOW_SECONDS` | `300` | Window for counting failed attempts (5 min) |
| `RATE_LIMIT_BAN_SECONDS` | `3600` | Temp ban duration (1 hour) |
| `RATE_LIMIT_PERM_BAN_THRESHOLD` | `3` | Temp bans before permanent ban |
| `SESSION_MAX_FAILED_ATTEMPTS` | `20` | Failed attempts before session is locked forever |
| `CREATE_RATE_LIMIT_MAX` | `30` | Per-IP session creations allowed in `CREATE_RATE_LIMIT_WINDOW_SECONDS`. Set ≤ 0 to disable. |
| `CREATE_RATE_LIMIT_WINDOW_SECONDS` | `3600` | Window for the create quota (1 hour) |
| `UPLOAD_RATE_LIMIT_MAX` | `60` | Per-IP uploads allowed in `UPLOAD_RATE_LIMIT_WINDOW_SECONDS`. Set ≤ 0 to disable. |
| `UPLOAD_RATE_LIMIT_WINDOW_SECONDS` | `3600` | Window for the upload quota (1 hour) |
| `APP_VERSION` | `1.4.0` | Version displayed in the footer |
| `DEBUG` | `false` | Enable FastAPI debug mode and `/docs` endpoint |

---

## Real-time sync

Connected browsers are updated in real time via **Server-Sent Events (SSE)**.  
A three-layer approach ensures no event is ever missed:

- **SSE** — instant push on new item, wipe, lock, or expiry
- **Page Visibility API** — immediate check when a tab regains focus after being hidden
- **Polling every 10s** — fallback covering tabs that stay visible on screen while activity happens elsewhere

The SSE heartbeat (every 25s) does **not** refresh the session TTL. See *Session lifetime* below for the exact rules.

---

## Session lifetime

A session lives for `SESSION_TTL_SECONDS` (2 h by default) from the last
event that the server considers a **real action**. The TTL is a sliding
window applied uniformly to all keys for a given session — text items
and files in the same session expire together.

**Refreshes the TTL:**
- Creating the session
- Adding a text item (`POST /{sid}/add`)
- Uploading a file (`POST /{sid}/upload`)

**Does NOT refresh the TTL:**
- Authenticating (`POST /{sid}/auth`) — proving you know the password
  is a read operation, not a write
- Loading or reloading the session page (`GET /{sid}`)
- Listing items, downloading files, SSE stream + heartbeats, polling
  fallback

This means: the countdown can only be extended by adding new content.
Reading and re-authentication are intentionally not enough to keep a
stale session alive indefinitely.

The "wipes in" countdown shown in the UI reflects the **real** Redis
expiry (passed to the page on render), not a hard-coded full TTL from
the page-load time — so a reload of a session that has 10 min left
correctly shows ~10 min, not "2 h".

---

## Data limits (defaults — all tunable via env)

- Max text item size: **500 KB**
- Max file size: **100 MiB** per file
- Max total file payload per session: **1 GiB**
- Global disk budget across all sessions: **10 GiB** — server-side stop before disk fills
- Per-IP create quota: **30 sessions / hour**
- Per-IP upload quota: **60 uploads / hour**
- No limit on number of text items per session
- All items are wiped after **2 hours of inactivity** or on manual wipe

When the global disk budget is reached, uploads receive `503 Service
Unavailable` with a `Retry-After` header. When the filesystem itself is
out of space (`ENOSPC`), uploads receive `507 Insufficient Storage`.

---

## Operations

### `/healthz` — liveness + storage probe

Anonymous JSON endpoint suitable for an external monitor (Uptime Kuma,
healthcheck.io, k8s probes, etc.):

```json
{
  "status": "ok",
  "reasons": [],
  "redis_ok": true,
  "disk_used_bytes": 0,
  "disk_cap_bytes": 10737418240,
  "disk_ratio": 0.0,
  "warn_ratio": 0.8,
  "version": "1.4.0"
}
```

- Returns **200** when Redis is reachable and `disk_ratio < HEALTHZ_WARN_RATIO`.
- Returns **503** otherwise. The `reasons` array (`"redis_unreachable"`,
  `"disk_over_threshold"`) surfaces the failure cause directly in the
  response body, which most monitors display on a failed heartbeat.

### Disk cleanup

A background task (`CLEANUP_INTERVAL_SECONDS`, default 600 s) purges
expired session directories from disk. Redis keys expire on their own
via TTL; this only reaps filesystem leftovers so disk usage doesn't
drift upward on a low-traffic deployment.

---

## Running tests

```bash
pip install -r app/requirements.txt pytest
pytest tests/ -v
```

---

## Session lifecycle

```
[Create]──────────────────────────────────────────────────────────────►[Active]
                                                                           │
                                              ┌────────────────────────────┤
                                              │                            │
                                         [Manual wipe]            [2h inactivity]
                                              │                            │
                                              └──────────►[Ended]◄─────────┘
                                                              │
                                                    [Data permanently gone]
```
