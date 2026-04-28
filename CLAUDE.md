# Hermes Agent Railway Template

## Architecture

Python/Starlette web server that wraps Hermes Agent's gateway as a managed subprocess.

- `server.py` — Main server: session sign-in, optional TOTP 2FA, HTTP handlers, gateway process manager, `.env` file management, file browser under `HERMES_HOME`
- `templates/index.html` — Single-page UI with Tailwind CSS + Alpine.js; `login.html` / `totp.html` for sign-in
- Config is stored as a flat `.env` file at `/data/.hermes/.env` (Hermes uses python-dotenv)
- Gateway is spawned via `hermes gateway` command with env vars from the .env file

## Key patterns

- Gateway lifecycle: start/stop/restart via async subprocess, stdout captured to ring buffer
- Secret masking: password fields show first 8 chars + `***`, merge on save preserves masked values
- No direct Hermes Python imports — the server manages the .env file independently
- Auto-start: gateway starts on server boot if any provider API key is configured
- TOTP 2FA: provisioning QR is shown only until the first successful verification for the current `ADMIN_TOTP_SECRET`; state file `.admin_totp_state.json` under `HERMES_HOME`
