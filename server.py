#!/usr/bin/env python3
import json
import os
import secrets
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse


ROOT_DIR = Path(__file__).resolve().parent
INDEX_FILE = os.getenv("INDEX_FILE", "index.html")
STATE_FILE = Path(os.getenv("STATE_FILE", str(ROOT_DIR / "live_state.json")))
MAX_STATE_BYTES = int(os.getenv("MAX_STATE_BYTES", str(64 * 1024 * 1024)))

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

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/me":
            self.end_json(HTTPStatus.OK, {"admin": self.is_admin_session()})
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
            if content_length > MAX_STATE_BYTES:
                self.end_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "state too large"})
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


def main():
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    server = HTTPServer((host, port), AppHandler)
    print(f"Serving on http://{host}:{port}")
    print("Set ADMIN_USERNAME / ADMIN_PASSWORD env vars for production.")
    server.serve_forever()


if __name__ == "__main__":
    main()
