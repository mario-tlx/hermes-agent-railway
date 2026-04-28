# Hermes Agent Railway Template

One-click deploy [Hermes Agent](https://github.com/nousresearch/hermes-agent) on [Railway](https://railway.app) with a web-based config UI and status dashboard.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/hermes-agent)

## What you get

- **Web Config UI** — configure LLM providers, messaging channels, tool API keys, and model settings from your browser
- **Status Dashboard** — monitor gateway state, uptime, provider/channel status, and live logs
- **Gateway Management** — start, stop, and restart the Hermes gateway from the UI
- **Admin sign-in** — session cookie after password; optional **TOTP / authenticator app** (RFC 6238) when `ADMIN_TOTP_SECRET` is set
- **Persistent Storage** — config and data survive container restarts via Railway volume

## Quick Start

### Deploy to Railway

1. Click the "Deploy on Railway" button above
2. Set the `ADMIN_PASSWORD` environment variable (or a random one will be generated and printed to logs)
3. **Optional 2FA:** set `ADMIN_TOTP_SECRET` to a **Base32** secret (see below) and set `ADMIN_SESSION_SECRET` to a long random string in production
4. Attach a volume mounted at `/data`
5. Open your app URL — use **Sign in** at `/login` (default username: `admin`)
6. Configure at least one LLM provider API key and your messaging channels, then hit Save
7. Once setup is complete, remove the public endpoint from your Railway service — the web UI is only needed for initial configuration and Hermes operates entirely through its configured channels (Telegram, Discord, Slack, etc.)

**Authenticator (TOTP):** Generate a Base32 secret (only letters A–Z and digits 2–7, often 16–32 characters). For example, with Python: `python -c "import secrets; print(secrets.token_hex(10).upper()[:20])"` is *not* Base32 — use instead: `python -c "import base64; import os; print(base64.b32encode(os.urandom(10)).decode().rstrip('='))"`. Put that value in Railway as `ADMIN_TOTP_SECRET`. After password login, scan the QR on the `/totp` page with Microsoft Authenticator, then enter the 6-digit code. Use **Sign out** when finished.

**Session signing:** Set `ADMIN_SESSION_SECRET` to a random string (e.g. 32+ bytes from `openssl rand -hex 32`). If unset, the server derives a key from `ADMIN_USERNAME` and `ADMIN_PASSWORD` (changing the password invalidates sessions).

### Run Locally with Docker

```bash
docker build -t hermes-agent .
docker run --rm -it -p 8080:8080 -e PORT=8080 -e ADMIN_PASSWORD=changeme -v hermes-data:/data hermes-agent
```

Open `http://localhost:8080/login` and sign in with `admin` / `changeme`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Web server port |
| `ADMIN_USERNAME` | `admin` | Sign-in username |
| `ADMIN_PASSWORD` | *(generated)* | Password. If unset, a random password is generated and printed to stdout |
| `ADMIN_TOTP_SECRET` | *(empty)* | Optional. Base32-encoded TOTP secret — enables authenticator-app step after password |
| `ADMIN_SESSION_SECRET` | *(derived)* | Optional. HMAC key for signed session cookies; set in production |

All Hermes configuration (LLM providers, messaging channels, tool API keys) is managed through the web UI after sign-in.

## Architecture

```
Railway Container
├── Python Web Server (Starlette + uvicorn)
│   ├── / — Config editor + status dashboard (session required)
│   ├── /login — password; /totp — authenticator when 2FA enabled
│   ├── /health — Health check (no auth)
│   └── /api/* — Config, status, logs, gateway control
└── hermes gateway — managed as async subprocess
```

The web server runs on `$PORT` and manages the Hermes gateway as a child process. Gateway stdout/stderr is captured into a ring buffer and viewable in the dashboard.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/login` | No | Sign-in form |
| `POST` | `/login` | No | Submit password |
| `GET` | `/totp` | Partial | TOTP form (after password) when 2FA enabled |
| `POST` | `/totp` | Partial | Submit 6-digit code |
| `POST` | `/logout` | Yes | End session |
| `GET` | `/api/auth/status` | No | `{ authenticated, totp_enabled, totp_pending }` |
| `GET` | `/` | Yes | Web UI |
| `GET` | `/health` | No | Health check |
| `GET` | `/api/config` | Yes | Get config (secrets masked) |
| `PUT` | `/api/config` | Yes | Save config |
| `GET` | `/api/status` | Yes | Gateway, provider, channel status |
| `GET` | `/api/logs` | Yes | Recent gateway log lines |
| `POST` | `/api/gateway/start` | Yes | Start gateway |
| `POST` | `/api/gateway/stop` | Yes | Stop gateway |
| `POST` | `/api/gateway/restart` | Yes | Restart gateway |

## Supported Providers

OpenRouter, DeepSeek, DashScope, GLM/Z.AI, Kimi, MiniMax, Hugging Face

## Supported Channels

Telegram, Discord, Slack, WhatsApp, Email, Mattermost, Matrix
