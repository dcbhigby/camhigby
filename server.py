#!/usr/bin/env python3
import json
import os
import secrets
import time
import hashlib
import re
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse


ROOT_DIR = Path(__file__).resolve().parent
INDEX_FILE = os.getenv("INDEX_FILE", "index.html")
DEFAULT_STATE_FILE = Path("/var/data/live_state.json") if Path("/var/data").exists() else (ROOT_DIR / "live_state.json")
STATE_FILE = Path(os.getenv("STATE_FILE", str(DEFAULT_STATE_FILE)))
MAX_STATE_BYTES = int(os.getenv("MAX_STATE_BYTES", str(256 * 1024 * 1024)))
DEFAULT_VIEWER_EMAIL_FILE = Path("/var/data/viewer_email_gate.json") if Path("/var/data").exists() else (ROOT_DIR / "viewer_email_gate.json")
VIEWER_EMAIL_FILE = Path(os.getenv("VIEWER_EMAIL_FILE", str(DEFAULT_VIEWER_EMAIL_FILE)))
VIEWER_EMAIL_COOKIE = "viewer_gate_pass"
VIEWER_EMAIL_TTL_SECONDS = int(os.getenv("VIEWER_EMAIL_TTL_SECONDS", str(30 * 24 * 60 * 60)))
IP_HASH_SALT = os.getenv("IP_HASH_SALT", "retro-war-map-ip-salt-v1")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "camhigby")
# Set this in your shell for production:
#   export ADMIN_PASSWORD='your-strong-password'
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CamHigbyAdmin2026!")
COOKIE_NAME = "admin_session"
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "43200"))  # 12 hours
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"

SESSIONS = {}  # token -> expiry_unix_ts


def now_ts() -> int:
    return int(time.time())


def prune_sessions() -> None:
    now = now_ts()
    expired = [tok for tok, exp in SESSIONS.items() if exp <= now]
    for tok in expired:
        SESSIONS.pop(tok, None)


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT_DIR), **kwargs)

    def log_message(self, fmt, *args):
        super().log_message(fmt, *args)

    def end_json(self, status: int, payload: dict, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def get_cookie_token(self):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            return None
        morsel = c.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def get_cookie_value(self, key: str):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            return None
        morsel = c.get(key)
        return morsel.value if morsel else None

    def is_admin_session(self):
        prune_sessions()
        tok = self.get_cookie_token()
        if not tok:
            return False
        exp = SESSIONS.get(tok)
        if not exp:
            return False
        if exp <= now_ts():
            SESSIONS.pop(tok, None)
            return False
        return True

    def make_session_cookie(self, token: str, max_age: int):
        parts = [
            f"{COOKIE_NAME}={token}",
            "HttpOnly",
            "Path=/",
            "SameSite=Lax",
            f"Max-Age={max_age}",
        ]
        if COOKIE_SECURE:
            parts.append("Secure")
        return "; ".join(parts)

    def make_viewer_gate_cookie(self, token: str, max_age: int):
        parts = [
            f"{VIEWER_EMAIL_COOKIE}={token}",
            "HttpOnly",
            "Path=/",
            "SameSite=Lax",
            f"Max-Age={max_age}",
        ]
        if COOKIE_SECURE:
            parts.append("Secure")
        return "; ".join(parts)

    def get_client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/me":
            self.end_json(HTTPStatus.OK, {"admin": self.is_admin_session()})
            return
        if path == "/api/viewer-email-status":
            cookie_ok = bool(self.get_cookie_value(VIEWER_EMAIL_COOKIE))
            ip_hash = hash_client_ip(self.get_client_ip())
            data = read_viewer_email_data()
            ip_ok = bool(data.get("byIp", {}).get(ip_hash))
            submitted = cookie_ok or ip_ok
            headers = None
            if submitted and not cookie_ok:
                headers = {"Set-Cookie": self.make_viewer_gate_cookie(secrets.token_urlsafe(18), VIEWER_EMAIL_TTL_SECONDS)}
            self.end_json(HTTPStatus.OK, {"ok": True, "submitted": submitted}, extra_headers=headers)
            return
        if path == "/api/state":
            payload = read_state_payload()
            if payload is None:
                self.end_json(HTTPStatus.OK, {"ok": True, "state": None})
            else:
                self.end_json(HTTPStatus.OK, payload)
            return

        if path in ("/", ""):
            self.path = "/" + INDEX_FILE
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/login":
            body = self.read_json_body()
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials"})
                return
            prune_sessions()
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = now_ts() + SESSION_TTL_SECONDS
            cookie = self.make_session_cookie(token, SESSION_TTL_SECONDS)
            self.end_json(
                HTTPStatus.OK,
                {"admin": True},
                extra_headers={"Set-Cookie": cookie},
            )
            return

        if path == "/api/logout":
            tok = self.get_cookie_token()
            if tok:
                SESSIONS.pop(tok, None)
            clear_cookie = self.make_session_cookie("", 0)
            self.end_json(
                HTTPStatus.OK,
                {"admin": False},
                extra_headers={"Set-Cookie": clear_cookie},
            )
            return
        if path == "/api/state":
            if not self.is_admin_session():
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "admin required"})
                return
            raw_len = self.headers.get("Content-Length", "0")
            try:
                content_length = int(raw_len)
            except ValueError:
                content_length = 0
            if content_length <= 0:
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "missing request body"})
                return
            if MAX_STATE_BYTES > 0 and content_length > MAX_STATE_BYTES:
                limit_mb = round(MAX_STATE_BYTES / (1024 * 1024), 2)
                self.end_json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": f"state too large (limit {limit_mb} MB)"},
                )
                return
            body = self.read_json_body()
            state = body.get("state")
            if not isinstance(state, dict):
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "state must be an object"})
                return
            saved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            payload = {"ok": True, "savedAt": saved_at, "state": state}
            try:
                write_state_payload(payload)
            except Exception as exc:
                self.end_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"failed to save state: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "savedAt": saved_at})
            return
        if path == "/api/viewer-email":
            body = self.read_json_body()
            email = str(body.get("email", "")).strip().lower()
            if not EMAIL_RE.match(email):
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "invalid email"})
                return
            ip_hash = hash_client_ip(self.get_client_ip())
            ua = str(body.get("userAgent", "")).strip()[:512]
            page = str(body.get("page", "")).strip()[:1024]
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            try:
                data = read_viewer_email_data()
                by_ip = data.setdefault("byIp", {})
                entries = data.setdefault("entries", [])
                by_ip[ip_hash] = {"email": email, "submittedAt": now_iso}
                entries.append({
                    "email": email,
                    "submittedAt": now_iso,
                    "ipHash": ip_hash,
                    "userAgent": ua,
                    "page": page,
                })
                # Keep log bounded.
                if len(entries) > 50000:
                    del entries[0 : len(entries) - 50000]
                write_viewer_email_data(data)
            except Exception as exc:
                self.end_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"failed to save viewer email: {exc}"})
                return
            self.end_json(
                HTTPStatus.OK,
                {"ok": True, "submitted": True},
                extra_headers={"Set-Cookie": self.make_viewer_gate_cookie(secrets.token_urlsafe(18), VIEWER_EMAIL_TTL_SECONDS)},
            )
            return

        self.end_json(HTTPStatus.NOT_FOUND, {"error": "not found"})


def read_state_payload():
    try:
        if not STATE_FILE.exists():
            return None
        raw = STATE_FILE.read_text(encoding="utf-8")
        if not raw.strip():
            return None
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        state = data.get("state")
        if not isinstance(state, dict):
            return None
        return {
            "ok": True,
            "savedAt": data.get("savedAt"),
            "state": state,
        }
    except Exception:
        return None


def write_state_payload(payload: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(STATE_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    tmp.replace(STATE_FILE)


def hash_client_ip(ip: str) -> str:
    base = f"{IP_HASH_SALT}:{ip or ''}".encode("utf-8")
    return hashlib.sha256(base).hexdigest()


def read_viewer_email_data() -> dict:
    try:
        if not VIEWER_EMAIL_FILE.exists():
            return {"byIp": {}, "entries": []}
        raw = VIEWER_EMAIL_FILE.read_text(encoding="utf-8")
        if not raw.strip():
            return {"byIp": {}, "entries": []}
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {"byIp": {}, "entries": []}
        by_ip = data.get("byIp")
        entries = data.get("entries")
        if not isinstance(by_ip, dict):
            by_ip = {}
        if not isinstance(entries, list):
            entries = []
        return {"byIp": by_ip, "entries": entries}
    except Exception:
        return {"byIp": {}, "entries": []}


def write_viewer_email_data(payload: dict):
    VIEWER_EMAIL_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = VIEWER_EMAIL_FILE.with_suffix(VIEWER_EMAIL_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    tmp.replace(VIEWER_EMAIL_FILE)


def main():
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    server = HTTPServer((host, port), AppHandler)
    print(f"Serving on http://{host}:{port}")
    print("Set ADMIN_USERNAME / ADMIN_PASSWORD env vars for production.")
    print(f"State file: {STATE_FILE}")
    server.serve_forever()


if __name__ == "__main__":
    main()
