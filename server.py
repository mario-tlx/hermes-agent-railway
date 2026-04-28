import asyncio
import hashlib
import io
import json
import os
import re
import secrets
import signal
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import unquote

import pyotp
import segno
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(16)
    print(f"Generated admin password: {ADMIN_PASSWORD}")

ADMIN_TOTP_SECRET = os.environ.get("ADMIN_TOTP_SECRET", "").strip().replace(" ", "").upper()
ADMIN_SESSION_SECRET = os.environ.get("ADMIN_SESSION_SECRET", "").strip()

SESSION_COOKIE = "hermes_admin_session"
TOTP_PENDING_COOKIE = "hermes_totp_pending"
SESSION_MAX_AGE = 7 * 24 * 3600
TOTP_PENDING_MAX_AGE = 600


def _session_signing_key() -> str:
    if ADMIN_SESSION_SECRET:
        return ADMIN_SESSION_SECRET
    material = f"{ADMIN_USERNAME}\x00{ADMIN_PASSWORD}\x00hermes-admin-session-v1".encode()
    return hashlib.sha256(material).hexdigest()


_session_serializer = URLSafeTimedSerializer(_session_signing_key(), salt="hermes-admin-session")
_totp_pending_serializer = URLSafeTimedSerializer(_session_signing_key(), salt="hermes-totp-pending")


def totp_enabled() -> bool:
    return bool(ADMIN_TOTP_SECRET)


def _totp() -> pyotp.TOTP | None:
    if not ADMIN_TOTP_SECRET:
        return None
    try:
        return pyotp.TOTP(ADMIN_TOTP_SECRET)
    except Exception:
        return None


def verify_totp_code(code: str) -> bool:
    if not isinstance(code, str):
        return False
    digits = "".join(c for c in code.strip() if c.isdigit())
    if len(digits) != 6:
        return False
    totp = _totp()
    if not totp:
        return False
    return bool(totp.verify(digits, valid_window=1))


def _set_session_cookie(response: Response, request: Request, username: str) -> None:
    token = _session_serializer.dumps({"u": username})
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_MAX_AGE, path="/", httponly=True, samesite="lax", secure=secure)


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(TOTP_PENDING_COOKIE, path="/")


def _set_totp_pending_cookie(response: Response, request: Request, username: str) -> None:
    token = _totp_pending_serializer.dumps({"u": username})
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"
    response.set_cookie(
        TOTP_PENDING_COOKIE,
        token,
        max_age=TOTP_PENDING_MAX_AGE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def get_session_username(request: Request) -> str | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        data = _session_serializer.loads(raw, max_age=SESSION_MAX_AGE)
        u = data.get("u")
        if isinstance(u, str) and u == ADMIN_USERNAME:
            return u
    except (BadSignature, SignatureExpired, TypeError, KeyError):
        pass
    return None


def get_totp_pending_username(request: Request) -> str | None:
    raw = request.cookies.get(TOTP_PENDING_COOKIE)
    if not raw:
        return None
    try:
        data = _totp_pending_serializer.loads(raw, max_age=TOTP_PENDING_MAX_AGE)
        u = data.get("u")
        if isinstance(u, str) and u == ADMIN_USERNAME:
            return u
    except (BadSignature, SignatureExpired, TypeError, KeyError):
        pass
    return None


def check_password(username: str, password: str) -> bool:
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD


def require_session(request: Request) -> Response | None:
    if get_session_username(request):
        return None
    if request.url.path.startswith("/api"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return RedirectResponse("/login", status_code=302)


HERMES_HOME = os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
ENV_FILE_PATH = Path(HERMES_HOME) / ".env"
PAIRING_DIR = Path(HERMES_HOME) / "pairing"
HERMES_ROOT = Path(HERMES_HOME).expanduser().resolve()
CODE_TTL_SECONDS = 3600
FILES_MAX_READ_BYTES = 512 * 1024

# Registry of known Hermes env vars exposed in the UI.
# Each entry: (key, label, category, is_password)
ENV_VAR_DEFS = [
    # Model
    ("LLM_MODEL", "Model", "model", False),
    # Providers
    ("OPENROUTER_API_KEY", "OpenRouter API Key", "provider", True),
    ("DEEPSEEK_API_KEY", "DeepSeek API Key", "provider", True),
    ("DASHSCOPE_API_KEY", "DashScope API Key", "provider", True),
    ("GLM_API_KEY", "GLM / Z.AI API Key", "provider", True),
    ("KIMI_API_KEY", "Kimi API Key", "provider", True),
    ("MINIMAX_API_KEY", "MiniMax API Key", "provider", True),
    ("HF_TOKEN", "Hugging Face Token", "provider", True),
    # Tools
    ("PARALLEL_API_KEY", "Parallel API Key", "tool", True),
    ("FIRECRAWL_API_KEY", "Firecrawl API Key", "tool", True),
    ("TAVILY_API_KEY", "Tavily API Key", "tool", True),
    ("FAL_KEY", "FAL API Key", "tool", True),
    ("BROWSERBASE_API_KEY", "Browserbase API Key", "tool", True),
    ("BROWSERBASE_PROJECT_ID", "Browserbase Project ID", "tool", False),
    ("GITHUB_TOKEN", "GitHub Token", "tool", True),
    ("VOICE_TOOLS_OPENAI_KEY", "OpenAI Voice Key", "tool", True),
    ("HONCHO_API_KEY", "Honcho API Key", "tool", True),
    # Messaging — Telegram
    ("TELEGRAM_BOT_TOKEN", "Telegram Bot Token", "messaging", True),
    ("TELEGRAM_ALLOWED_USERS", "Telegram Allowed Users", "messaging", False),
    # Messaging — Discord
    ("DISCORD_BOT_TOKEN", "Discord Bot Token", "messaging", True),
    ("DISCORD_ALLOWED_USERS", "Discord Allowed Users", "messaging", False),
    # Messaging — Slack
    ("SLACK_BOT_TOKEN", "Slack Bot Token", "messaging", True),
    ("SLACK_APP_TOKEN", "Slack App Token", "messaging", True),
    # Messaging — WhatsApp
    ("WHATSAPP_ENABLED", "WhatsApp Enabled", "messaging", False),
    # Messaging — Email
    ("EMAIL_ADDRESS", "Email Address", "messaging", False),
    ("EMAIL_PASSWORD", "Email Password", "messaging", True),
    ("EMAIL_IMAP_HOST", "Email IMAP Host", "messaging", False),
    ("EMAIL_SMTP_HOST", "Email SMTP Host", "messaging", False),
    # Messaging — Mattermost
    ("MATTERMOST_URL", "Mattermost URL", "messaging", False),
    ("MATTERMOST_TOKEN", "Mattermost Token", "messaging", True),
    # Messaging — Matrix
    ("MATRIX_HOMESERVER", "Matrix Homeserver", "messaging", False),
    ("MATRIX_ACCESS_TOKEN", "Matrix Access Token", "messaging", True),
    ("MATRIX_USER_ID", "Matrix User ID", "messaging", False),
    # Messaging — General
    ("GATEWAY_ALLOW_ALL_USERS", "Allow All Users", "messaging", False),
]

PASSWORD_KEYS = {key for key, _, _, is_pw in ENV_VAR_DEFS if is_pw}

PROVIDER_KEYS = [key for key, _, cat, _ in ENV_VAR_DEFS if cat == "provider" and key != "LLM_MODEL"]
CHANNEL_KEYS = {
    "Telegram": "TELEGRAM_BOT_TOKEN",
    "Discord": "DISCORD_BOT_TOKEN",
    "Slack": "SLACK_BOT_TOKEN",
    "WhatsApp": "WHATSAPP_ENABLED",
    "Email": "EMAIL_ADDRESS",
    "Mattermost": "MATTERMOST_TOKEN",
    "Matrix": "MATRIX_ACCESS_TOKEN",
}


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key] = value
    return result


def write_env_file(path: Path, env_vars: dict[str, str]):
    path.parent.mkdir(parents=True, exist_ok=True)

    categories = {"model": "Model", "provider": "Providers", "tool": "Tools", "messaging": "Messaging"}
    grouped: dict[str, list[str]] = {cat: [] for cat in categories}
    known_keys = {key for key, _, _, _ in ENV_VAR_DEFS}
    key_to_cat = {key: cat for key, _, cat, _ in ENV_VAR_DEFS}

    for key, value in env_vars.items():
        if not value:
            continue
        cat = key_to_cat.get(key, "other")
        line = f"{key}={value}"
        if cat in grouped:
            grouped[cat].append(line)
        else:
            grouped.setdefault("other", []).append(line)

    lines = []
    for cat, heading in categories.items():
        entries = grouped.get(cat, [])
        if entries:
            lines.append(f"# {heading}")
            lines.extend(sorted(entries))
            lines.append("")

    other = grouped.get("other", [])
    if other:
        lines.append("# Other")
        lines.extend(sorted(other))
        lines.append("")

    path.write_text("\n".join(lines) + "\n" if lines else "")


def mask_secrets(env_vars: dict[str, str]) -> dict[str, str]:
    result = {}
    for key, value in env_vars.items():
        if key in PASSWORD_KEYS and value:
            result[key] = value[:8] + "***" if len(value) > 8 else "***"
        else:
            result[key] = value
    return result


def merge_secrets(new_vars: dict[str, str], existing_vars: dict[str, str]) -> dict[str, str]:
    result = {}
    for key, value in new_vars.items():
        if key in PASSWORD_KEYS and value.endswith("***"):
            result[key] = existing_vars.get(key, "")
        else:
            result[key] = value
    return result


class GatewayManager:
    def __init__(self):
        self.process: asyncio.subprocess.Process | None = None
        self.state = "stopped"
        self.logs: deque[str] = deque(maxlen=500)
        self.start_time: float | None = None
        self.restart_count = 0
        self._read_tasks: list[asyncio.Task] = []

    async def start(self):
        if self.process and self.process.returncode is None:
            return
        self.state = "starting"
        try:
            env = os.environ.copy()
            env["HERMES_HOME"] = HERMES_HOME
            env_vars = read_env_file(ENV_FILE_PATH)
            env.update(env_vars)

            self.process = await asyncio.create_subprocess_exec(
                "hermes", "gateway",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            self.state = "running"
            self.start_time = time.time()
            task = asyncio.create_task(self._read_output())
            self._read_tasks.append(task)
        except Exception as e:
            self.state = "error"
            self.logs.append(f"Failed to start gateway: {e}")

    async def stop(self):
        if not self.process or self.process.returncode is not None:
            self.state = "stopped"
            return
        self.state = "stopping"
        self.process.terminate()
        try:
            await asyncio.wait_for(self.process.wait(), timeout=10)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()
        self.state = "stopped"
        self.start_time = None

    async def restart(self):
        await self.stop()
        self.restart_count += 1
        await self.start()

    async def _read_output(self):
        try:
            while self.process and self.process.stdout:
                line = await self.process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                cleaned = ANSI_ESCAPE.sub("", decoded)
                self.logs.append(cleaned)
        except asyncio.CancelledError:
            return
        if self.process and self.process.returncode is not None and self.state == "running":
            self.state = "error"
            self.logs.append(f"Gateway exited with code {self.process.returncode}")

    def get_status(self) -> dict:
        pid = None
        if self.process and self.process.returncode is None:
            pid = self.process.pid
        uptime = None
        if self.start_time and self.state == "running":
            uptime = int(time.time() - self.start_time)
        return {
            "state": self.state,
            "pid": pid,
            "uptime": uptime,
            "restart_count": self.restart_count,
        }


gateway = GatewayManager()
config_lock = asyncio.Lock()


if ADMIN_TOTP_SECRET and _totp() is None:
    print("WARNING: ADMIN_TOTP_SECRET is set but invalid for TOTP (expect base32). 2FA will not work until fixed.")


async def login_page(request: Request):
    if get_session_username(request):
        return RedirectResponse("/", status_code=302)
    if totp_enabled() and get_totp_pending_username(request):
        return RedirectResponse("/totp", status_code=302)
    err = request.query_params.get("error", "")
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": err, "username_default": ADMIN_USERNAME},
    )


async def login_submit(request: Request):
    if get_session_username(request):
        return RedirectResponse("/", status_code=302)
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "")
    if not check_password(username, password):
        return RedirectResponse("/login?error=1", status_code=302)
    if totp_enabled():
        resp = RedirectResponse("/totp", status_code=302)
        _set_totp_pending_cookie(resp, request, username)
        return resp
    resp = RedirectResponse("/", status_code=302)
    _set_session_cookie(resp, request, username)
    return resp


async def totp_page(request: Request):
    if get_session_username(request):
        return RedirectResponse("/", status_code=302)
    if not totp_enabled():
        return RedirectResponse("/login", status_code=302)
    if not get_totp_pending_username(request):
        return RedirectResponse("/login", status_code=302)
    err = request.query_params.get("error", "")
    totp = _totp()
    if not totp:
        return RedirectResponse("/login?error=1", status_code=302)
    issuer = "Hermes Admin"
    account = ADMIN_USERNAME
    uri = totp.provisioning_uri(name=account, issuer_name=issuer)
    return templates.TemplateResponse(
        request,
        "totp.html",
        {"error": err, "issuer": issuer, "account": account},
    )


async def totp_qr_png(request: Request):
    if not totp_enabled():
        return PlainTextResponse("Not found", status_code=404)
    if not get_totp_pending_username(request):
        return PlainTextResponse("Unauthorized", status_code=401)
    totp = _totp()
    if not totp:
        return PlainTextResponse("Not found", status_code=404)
    uri = totp.provisioning_uri(name=ADMIN_USERNAME, issuer_name="Hermes Admin")
    qr = segno.make(uri, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=4)
    return Response(content=buf.getvalue(), media_type="image/png")


async def totp_submit(request: Request):
    if get_session_username(request):
        return RedirectResponse("/", status_code=302)
    if not get_totp_pending_username(request):
        return RedirectResponse("/login", status_code=302)
    form = await request.form()
    code = form.get("code") or ""
    if not verify_totp_code(str(code)):
        return RedirectResponse("/totp?error=1", status_code=302)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(TOTP_PENDING_COOKIE, path="/")
    _set_session_cookie(resp, request, ADMIN_USERNAME)
    return resp


async def logout(request: Request):
    resp = RedirectResponse("/login", status_code=302)
    _clear_session_cookies(resp)
    return resp


async def api_auth_status(request: Request):
    return JSONResponse({
        "authenticated": bool(get_session_username(request)),
        "totp_enabled": totp_enabled(),
        "totp_pending": bool(get_totp_pending_username(request)),
    })


async def homepage(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    return templates.TemplateResponse(request, "index.html")


async def health(request: Request):
    return JSONResponse({"status": "ok", "gateway": gateway.state})


async def api_config_get(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    async with config_lock:
        env_vars = read_env_file(ENV_FILE_PATH)
    defs = [
        {"key": key, "label": label, "category": cat, "password": is_pw}
        for key, label, cat, is_pw in ENV_VAR_DEFS
    ]
    return JSONResponse({"vars": mask_secrets(env_vars), "defs": defs})


async def api_config_put(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    try:
        restart = body.pop("_restartGateway", False)
        new_vars = body.get("vars", {})

        async with config_lock:
            existing = read_env_file(ENV_FILE_PATH)
            merged = merge_secrets(new_vars, existing)
            # Preserve any existing vars not in the UI
            for key, value in existing.items():
                if key not in merged:
                    merged[key] = value
            write_env_file(ENV_FILE_PATH, merged)

        if restart:
            asyncio.create_task(gateway.restart())

        return JSONResponse({"ok": True, "restarting": restart})
    except Exception as e:
        print(f"Config save error: {type(e).__name__}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_status(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err

    env_vars = read_env_file(ENV_FILE_PATH)

    providers = {}
    for key in PROVIDER_KEYS:
        label = key.replace("_API_KEY", "").replace("_TOKEN", "").replace("HF_", "HuggingFace ").replace("_", " ").title()
        providers[label] = {"configured": bool(env_vars.get(key))}

    channels = {}
    for name, key in CHANNEL_KEYS.items():
        val = env_vars.get(key, "")
        channels[name] = {"configured": bool(val) and val.lower() not in ("false", "0", "no")}

    return JSONResponse({
        "gateway": gateway.get_status(),
        "providers": providers,
        "channels": channels,
    })


async def api_logs(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    return JSONResponse({"lines": list(gateway.logs)})


async def api_gateway_start(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.start())
    return JSONResponse({"ok": True})


async def api_gateway_stop(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.stop())
    return JSONResponse({"ok": True})


async def api_gateway_restart(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.restart())
    return JSONResponse({"ok": True})


def _load_pairing_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_pairing_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _pairing_platforms(suffix: str) -> list[str]:
    if not PAIRING_DIR.exists():
        return []
    return [
        f.stem.rsplit(f"-{suffix}", 1)[0]
        for f in PAIRING_DIR.glob(f"*-{suffix}.json")
    ]


async def api_pairing_pending(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    now = time.time()
    results = []
    for platform in _pairing_platforms("pending"):
        pending = _load_pairing_json(PAIRING_DIR / f"{platform}-pending.json")
        for code, info in pending.items():
            age = now - info.get("created_at", now)
            if age > CODE_TTL_SECONDS:
                continue
            results.append({
                "platform": platform,
                "code": code,
                "user_id": info.get("user_id", ""),
                "user_name": info.get("user_name", ""),
                "age_minutes": int(age / 60),
            })
    return JSONResponse({"pending": results})


async def api_pairing_approve(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    platform = body.get("platform", "")
    code = body.get("code", "").upper().strip()
    if not platform or not code:
        return JSONResponse({"error": "platform and code required"}, status_code=400)

    pending_path = PAIRING_DIR / f"{platform}-pending.json"
    pending = _load_pairing_json(pending_path)
    if code not in pending:
        return JSONResponse({"error": "Code not found or expired"}, status_code=404)

    entry = pending.pop(code)
    _save_pairing_json(pending_path, pending)

    approved_path = PAIRING_DIR / f"{platform}-approved.json"
    approved = _load_pairing_json(approved_path)
    approved[entry["user_id"]] = {
        "user_name": entry.get("user_name", ""),
        "approved_at": time.time(),
    }
    _save_pairing_json(approved_path, approved)

    return JSONResponse({"ok": True, "user_id": entry["user_id"], "user_name": entry.get("user_name", "")})


async def api_pairing_deny(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    platform = body.get("platform", "")
    code = body.get("code", "").upper().strip()
    if not platform or not code:
        return JSONResponse({"error": "platform and code required"}, status_code=400)

    pending_path = PAIRING_DIR / f"{platform}-pending.json"
    pending = _load_pairing_json(pending_path)
    if code in pending:
        del pending[code]
        _save_pairing_json(pending_path, pending)

    return JSONResponse({"ok": True})


async def api_pairing_approved(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    results = []
    for platform in _pairing_platforms("approved"):
        approved = _load_pairing_json(PAIRING_DIR / f"{platform}-approved.json")
        for user_id, info in approved.items():
            results.append({
                "platform": platform,
                "user_id": user_id,
                "user_name": info.get("user_name", ""),
                "approved_at": info.get("approved_at", 0),
            })
    return JSONResponse({"approved": results})


async def api_pairing_revoke(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    platform = body.get("platform", "")
    user_id = body.get("user_id", "")
    if not platform or not user_id:
        return JSONResponse({"error": "platform and user_id required"}, status_code=400)

    approved_path = PAIRING_DIR / f"{platform}-approved.json"
    approved = _load_pairing_json(approved_path)
    if user_id in approved:
        del approved[user_id]
        _save_pairing_json(approved_path, approved)

    return JSONResponse({"ok": True})


def resolve_safe_relpath(relpath: str) -> tuple[Path | None, str | None]:
    """Resolve a path relative to HERMES_ROOT. Rejects traversal and null bytes."""
    if not isinstance(relpath, str):
        relpath = ""
    raw = unquote(relpath).replace("\\", "/")
    if "\x00" in raw:
        return None, "Invalid path"
    trimmed = raw.strip("/")
    parts = [p for p in trimmed.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        return None, "Invalid path"
    candidate = HERMES_ROOT.joinpath(*parts) if parts else HERMES_ROOT
    try:
        resolved = candidate.resolve()
    except OSError:
        return None, "Invalid path"
    try:
        resolved.relative_to(HERMES_ROOT)
    except ValueError:
        return None, "Path escapes Hermes home"
    return resolved, None


def _files_list_sync(abs_path: Path) -> dict:
    entries = []
    for name in sorted(abs_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        try:
            st = name.stat()
        except OSError:
            continue
        entries.append({
            "name": name.name,
            "is_dir": name.is_dir(),
            "size": st.st_size if name.is_file() else None,
            "mtime": int(st.st_mtime),
        })
    return {"path": str(abs_path.relative_to(HERMES_ROOT)) if abs_path != HERMES_ROOT else "", "entries": entries}


async def api_files_list(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    relpath = request.query_params.get("path", "")
    abs_path, err = resolve_safe_relpath(relpath)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    if not abs_path.exists():
        return JSONResponse({"error": "Not found"}, status_code=404)
    if not abs_path.is_dir():
        return JSONResponse({"error": "Not a directory"}, status_code=400)
    try:
        data = await asyncio.to_thread(_files_list_sync, abs_path)
    except PermissionError:
        return JSONResponse({"error": "Permission denied"}, status_code=403)
    except OSError as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse(data)


async def api_files_read(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    relpath = request.query_params.get("path", "")
    abs_path, err = resolve_safe_relpath(relpath)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    if not abs_path.exists():
        return JSONResponse({"error": "Not found"}, status_code=404)
    if not abs_path.is_file():
        return JSONResponse({"error": "Not a file"}, status_code=400)

    def read_sync() -> tuple[str | None, str | None, int | None]:
        try:
            size = abs_path.stat().st_size
        except OSError as e:
            return None, str(e), None
        if size > FILES_MAX_READ_BYTES:
            return None, f"File too large (max {FILES_MAX_READ_BYTES} bytes)", size
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return None, str(e), size
        return text, None, size

    try:
        content, read_err, size = await asyncio.to_thread(read_sync)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    if read_err:
        code = 413 if "too large" in read_err else 400
        return JSONResponse({"error": read_err, "size": size}, status_code=code)
    rel = str(abs_path.relative_to(HERMES_ROOT)) if abs_path != HERMES_ROOT else ""
    return JSONResponse({"path": rel, "content": content, "size": size})


async def api_files_save(request: Request):
    auth_err = require_session(request)
    if auth_err:
        return auth_err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    relpath = body.get("path", "")
    if not isinstance(relpath, str):
        relpath = ""
    content = body.get("content", "")
    if not isinstance(content, str):
        return JSONResponse({"error": "content must be a string"}, status_code=400)

    if len(content.encode("utf-8")) > FILES_MAX_READ_BYTES:
        return JSONResponse(
            {"error": f"Content too large (max {FILES_MAX_READ_BYTES} bytes)"},
            status_code=413,
        )

    abs_path, err = resolve_safe_relpath(relpath)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    if abs_path.exists() and not abs_path.is_file():
        return JSONResponse({"error": "Not a file"}, status_code=400)

    def write_sync() -> str | None:
        try:
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            abs_path.write_bytes(content.encode("utf-8"))
        except OSError as e:
            return str(e)
        return None

    try:
        write_err = await asyncio.to_thread(write_sync)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    if write_err:
        return JSONResponse({"error": write_err}, status_code=500)

    rel = str(abs_path.relative_to(HERMES_ROOT)) if abs_path != HERMES_ROOT else ""
    try:
        new_size = abs_path.stat().st_size
    except OSError:
        new_size = len(content.encode("utf-8"))
    return JSONResponse({"ok": True, "path": rel, "size": new_size})


async def auto_start_gateway():
    env_vars = read_env_file(ENV_FILE_PATH)
    has_provider = any(env_vars.get(key) for key in PROVIDER_KEYS)
    if has_provider:
        asyncio.create_task(gateway.start())


routes = [
    Route("/login", login_page, methods=["GET"]),
    Route("/login", login_submit, methods=["POST"]),
    Route("/totp", totp_page, methods=["GET"]),
    Route("/totp", totp_submit, methods=["POST"]),
    Route("/totp/qr.png", totp_qr_png, methods=["GET"]),
    Route("/logout", logout, methods=["POST"]),
    Route("/api/auth/status", api_auth_status, methods=["GET"]),
    Route("/", homepage),
    Route("/health", health),
    Route("/api/config", api_config_get, methods=["GET"]),
    Route("/api/config", api_config_put, methods=["PUT"]),
    Route("/api/status", api_status),
    Route("/api/logs", api_logs),
    Route("/api/gateway/start", api_gateway_start, methods=["POST"]),
    Route("/api/gateway/stop", api_gateway_stop, methods=["POST"]),
    Route("/api/gateway/restart", api_gateway_restart, methods=["POST"]),
    Route("/api/pairing/pending", api_pairing_pending),
    Route("/api/pairing/approve", api_pairing_approve, methods=["POST"]),
    Route("/api/pairing/deny", api_pairing_deny, methods=["POST"]),
    Route("/api/pairing/approved", api_pairing_approved),
    Route("/api/pairing/revoke", api_pairing_revoke, methods=["POST"]),
    Route("/api/files/list", api_files_list),
    Route("/api/files/read", api_files_read),
    Route("/api/files/save", api_files_save, methods=["POST"]),
]

@asynccontextmanager
async def lifespan(app):
    await auto_start_gateway()
    yield
    await gateway.stop()


app = Starlette(
    routes=routes,
    lifespan=lifespan,
)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
    server = uvicorn.Server(config)

    def handle_signal():
        loop.create_task(gateway.stop())
        server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    loop.run_until_complete(server.serve())
