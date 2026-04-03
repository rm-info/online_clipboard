# Online Clipboard

Secure, ephemeral clipboard sharing between machines that cannot communicate directly.  
Designed for RDP sessions where clipboard sync is disabled, or any scenario requiring
a quick, passwordless (or password-protected) data transfer between two browsers.

---

## How it works

1. **Paste** your data on Machine A, optionally set a password, create a session
2. **Share** the session URL with Machine B
3. **Retrieve** and read your data within 2 hours
4. **Everything is wiped automatically** — no traces left after 2 hours of inactivity

Sessions can also be wiped manually at any time via the "Wipe session" button.

---

## Security model

| Layer | Mechanism |
|---|---|
| Encryption | AES-256-GCM (authenticated — detects tampering) |
| Key derivation | Argon2id — password + server secret → 256-bit key |
| Server pepper | `CLIPBOARD_SERVER_SECRET` — Redis dump useless without it |
| Transport | HTTPS only, HSTS enforced via Nginx |
| Session TTL | 2-hour sliding window, reset only on real activity (not heartbeats) |
| Brute force | IP rate limiting → temp ban → permanent ban |
| Session lockdown | Auto-lock after too many failed attempts, data wiped immediately |
| No plaintext | Data never stored unencrypted, password never visible in JS |

### Password handling

The password is stored server-side in an `httponly` cookie — JavaScript never has access to it.  
Whether a session has a password or not is never revealed to unauthenticated visitors.  
Submitting a non-empty password on a passwordless session is treated as a wrong password.

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

App available at `http://localhost:8000`.  
Put Nginx in front for production (see `nginx.conf`).

---

## Production deployment (Nginx + Let's Encrypt)

```bash
# Get a TLS certificate
certbot certonly --nginx -d your.domain.com

# Install Nginx config
cp nginx.conf /etc/nginx/sites-available/clipboard
# Edit: replace 'your.domain.com' with your actual domain
ln -s /etc/nginx/sites-available/clipboard /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

---

## Project structure

```
├── app/
│   ├── main.py         # FastAPI routes
│   ├── crypto.py       # AES-256-GCM encryption + Argon2id KDF
│   ├── session.py      # Redis session management + pub/sub
│   ├── security.py     # IP rate limiting and ban logic
│   ├── config.py       # Environment configuration
│   ├── static/         # Static assets
│   └── templates/
│       ├── base.html       # Base layout + styles
│       ├── index.html      # Session creation form
│       ├── auth.html       # Authentication form
│       ├── session.html    # Active session view
│       ├── locked.html     # Locked session page
│       └── not_found.html  # Expired/unknown session page
├── tests/
│   └── test_crypto.py  # Crypto unit tests
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
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
| `RATE_LIMIT_MAX_ATTEMPTS` | `10` | Failed auth attempts before temp ban |
| `RATE_LIMIT_WINDOW_SECONDS` | `300` | Window for counting failed attempts (5 min) |
| `RATE_LIMIT_BAN_SECONDS` | `3600` | Temp ban duration (1 hour) |
| `RATE_LIMIT_PERM_BAN_THRESHOLD` | `3` | Temp bans before permanent ban |
| `SESSION_MAX_FAILED_ATTEMPTS` | `20` | Failed attempts before session is locked forever |
| `APP_VERSION` | `1.0.0` | Version displayed in the footer |
| `DEBUG` | `false` | Enable FastAPI debug mode and `/docs` endpoint |

---

## Real-time sync

Connected browsers are updated in real time via **Server-Sent Events (SSE)**.  
A three-layer approach ensures no event is ever missed:

- **SSE** — instant push on new item, wipe, lock, or expiry
- **Page Visibility API** — immediate check when a tab regains focus after being hidden
- **Polling every 10s** — fallback covering tabs that stay visible on screen while activity happens elsewhere

The SSE heartbeat (every 25s) does **not** refresh the session TTL — only real actions do (adding an item, authenticating).

---

## Data limits

- Max item size: **500 KB**
- No limit on number of items per session
- All items are wiped after **2 hours of inactivity** or on manual wipe

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