#!/usr/bin/env python3
import json
import os
import secrets
import time
import hashlib
import hmac
import re
import gzip
import html
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs


ROOT_DIR = Path(__file__).resolve().parent
INDEX_FILE = os.getenv("INDEX_FILE", "index.html")
DEFAULT_STATE_FILE = Path("/var/data/live_state.json") if Path("/var/data").exists() else (ROOT_DIR / "live_state.json")
STATE_FILE = Path(os.getenv("STATE_FILE", str(DEFAULT_STATE_FILE)))
STATE_BACKUP_FILE = Path(os.getenv("STATE_BACKUP_FILE", str(STATE_FILE.with_suffix(".backup.json"))))
STATE_LITE_FILE = Path(os.getenv("STATE_LITE_FILE", str(STATE_FILE.with_name(STATE_FILE.stem + ".lite.json"))))
MAX_STATE_BYTES = int(os.getenv("MAX_STATE_BYTES", "0"))
DEFAULT_VIEWER_EMAIL_FILE = Path("/var/data/viewer_email_gate.json") if Path("/var/data").exists() else (ROOT_DIR / "viewer_email_gate.json")
VIEWER_EMAIL_FILE = Path(os.getenv("VIEWER_EMAIL_FILE", str(DEFAULT_VIEWER_EMAIL_FILE)))
DEFAULT_MANUAL_REPORTS_FILE = Path("/var/data/manual_reports.json") if Path("/var/data").exists() else (ROOT_DIR / "manual_reports.json")
MANUAL_REPORTS_FILE = Path(os.getenv("MANUAL_REPORTS_FILE", str(DEFAULT_MANUAL_REPORTS_FILE)))
DEFAULT_STRIKE_REPORTS_FILE = Path("/var/data/strike_reports.json") if Path("/var/data").exists() else (ROOT_DIR / "strike_reports.json")
STRIKE_REPORTS_FILE = Path(os.getenv("STRIKE_REPORTS_FILE", str(DEFAULT_STRIKE_REPORTS_FILE)))
MAX_STRIKE_REPORTS = int(os.getenv("MAX_STRIKE_REPORTS", "5000"))
STRIKE_REPORT_NOTES_MAX_CHARS = int(os.getenv("STRIKE_REPORT_NOTES_MAX_CHARS", "200"))
STRIKE_REPORT_TITLE_MAX_CHARS = int(os.getenv("STRIKE_REPORT_TITLE_MAX_CHARS", "140"))
STRIKE_REPORT_IMAGE_MARGIN_BYTES = int(os.getenv("STRIKE_REPORT_IMAGE_MARGIN_BYTES", str(256 * 1024)))
STRIKE_REPORT_MIN_IMAGE_BYTES = int(os.getenv("STRIKE_REPORT_MIN_IMAGE_BYTES", str(512 * 1024)))
STRIKE_REPORT_MAX_IMAGE_BYTES = int(os.getenv("STRIKE_REPORT_MAX_IMAGE_BYTES", str(8 * 1024 * 1024)))
STRIKE_REPORT_MAX_PAYLOAD_OVERHEAD = int(os.getenv("STRIKE_REPORT_MAX_PAYLOAD_OVERHEAD", str(128 * 1024)))
VIEWER_EMAIL_COOKIE = "viewer_gate_pass"
VIEWER_EMAIL_TTL_SECONDS = int(os.getenv("VIEWER_EMAIL_TTL_SECONDS", str(30 * 24 * 60 * 60)))
IP_HASH_SALT = os.getenv("IP_HASH_SALT", "retro-war-map-ip-salt-v1")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "camhigby")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "").strip()
ADMIN_PASSWORD_SALT = os.getenv("ADMIN_PASSWORD_SALT", "").strip()
ADMIN_PASSWORD_PEPPER = os.getenv("ADMIN_PASSWORD_PEPPER", "").strip()
ADMIN_PASSWORD_PBKDF2_ITER = int(os.getenv("ADMIN_PASSWORD_PBKDF2_ITER", "310000"))
COOKIE_NAME = "admin_session"
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "43200"))  # 12 hours
COOKIE_SECURE_MODE = os.getenv("COOKIE_SECURE", "auto").strip().lower()
APP_REV = os.getenv("APP_REV", os.getenv("RENDER_GIT_COMMIT", "dev"))[:40]
AI_IMAGE_DETECT_PROVIDER = os.getenv("AI_IMAGE_DETECT_PROVIDER", "sightengine").strip().lower()
SIGHTENGINE_API_USER = os.getenv("SIGHTENGINE_API_USER", "").strip()
SIGHTENGINE_API_SECRET = os.getenv("SIGHTENGINE_API_SECRET", "").strip()
AI_DETECT_TIMEOUT_SECONDS = float(os.getenv("AI_DETECT_TIMEOUT_SECONDS", "8"))
X_BEARER_TOKEN = os.getenv("X_BEARER_TOKEN", "").strip()
X_API_TIMEOUT_SECONDS = float(os.getenv("X_API_TIMEOUT_SECONDS", "10"))
X_API_BASE_URL = os.getenv("X_API_BASE_URL", "https://api.twitter.com").strip().rstrip("/")
TELEGRAM_CHANNELS = [x.strip().lstrip("@") for x in os.getenv("TELEGRAM_CHANNELS", "").split(",") if x.strip()]
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_VISION_MODEL = os.getenv("OPENAI_VISION_MODEL", "gpt-4.1-mini").strip()
OPENAI_TIMEOUT_SECONDS = float(os.getenv("OPENAI_TIMEOUT_SECONDS", "12"))

SESSIONS = {}  # token -> expiry_unix_ts
STATE_WRITE_LOCK = threading.Lock()
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_STATE = {}  # (bucket, key) -> [timestamps]
LOGIN_FAIL_LOCK = threading.Lock()
LOGIN_FAIL_STATE = {}  # ip -> {"fails": int, "lock_until": int}

LOGIN_RATE_WINDOW_SEC = int(os.getenv("LOGIN_RATE_WINDOW_SEC", "300"))
LOGIN_RATE_MAX_ATTEMPTS = int(os.getenv("LOGIN_RATE_MAX_ATTEMPTS", "20"))
LOGIN_LOCK_FAIL_THRESHOLD = int(os.getenv("LOGIN_LOCK_FAIL_THRESHOLD", "5"))
LOGIN_LOCK_DURATION_SEC = int(os.getenv("LOGIN_LOCK_DURATION_SEC", "900"))
STRIKE_REPORT_RATE_WINDOW_SEC = int(os.getenv("STRIKE_REPORT_RATE_WINDOW_SEC", "300"))
STRIKE_REPORT_RATE_MAX_ATTEMPTS = int(os.getenv("STRIKE_REPORT_RATE_MAX_ATTEMPTS", "6"))
VIEWER_EMAIL_RATE_WINDOW_SEC = int(os.getenv("VIEWER_EMAIL_RATE_WINDOW_SEC", "300"))
VIEWER_EMAIL_RATE_MAX_ATTEMPTS = int(os.getenv("VIEWER_EMAIL_RATE_MAX_ATTEMPTS", "12"))


def now_ts() -> int:
    return int(time.time())


def derive_admin_password_hex(password: str, salt: str, iterations: int, pepper: str = "") -> str:
    pwd = f"{password}{pepper}".encode("utf-8")
    salt_b = str(salt).encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", pwd, salt_b, max(1, int(iterations)))
    return dk.hex()


def verify_admin_password(candidate_password: str) -> bool:
    candidate = str(candidate_password or "")
    expected_hash = str(ADMIN_PASSWORD_HASH or "").strip()
    pepper = str(ADMIN_PASSWORD_PEPPER or "")
    if not expected_hash:
        # Compatibility fallback: allow env-based plaintext password when hash mode is not configured.
        legacy = str(ADMIN_PASSWORD or "")
        return bool(legacy) and hmac.compare_digest(candidate, legacy)
    # Preferred mode: structured hash string pbkdf2_sha256$<iterations>$<salt>$<hex>
    try:
        if expected_hash.startswith("pbkdf2_sha256$"):
            _alg, it_s, salt_s, hex_s = expected_hash.split("$", 3)
            derived = derive_admin_password_hex(candidate, salt_s, int(it_s), pepper=pepper)
            return hmac.compare_digest(derived, hex_s.strip().lower())
        # Compatible mode: hash in ADMIN_PASSWORD_HASH + separate salt/iter env vars
        if ADMIN_PASSWORD_SALT:
            derived = derive_admin_password_hex(candidate, ADMIN_PASSWORD_SALT, ADMIN_PASSWORD_PBKDF2_ITER, pepper=pepper)
            return hmac.compare_digest(derived, expected_hash.lower())
        return False
    except Exception:
        return False


def prune_sessions() -> None:
    now = now_ts()
    expired = [tok for tok, exp in SESSIONS.items() if exp <= now]
    for tok in expired:
        SESSIONS.pop(tok, None)


def rate_limit_check(bucket: str, key: str, limit: int, window_sec: int):
    if not bucket or not key or limit <= 0 or window_sec <= 0:
        return True, 0
    now = now_ts()
    cutoff = now - window_sec
    idx = (bucket, key)
    with RATE_LIMIT_LOCK:
        arr = RATE_LIMIT_STATE.get(idx, [])
        arr = [t for t in arr if t > cutoff]
        if len(arr) >= limit:
            retry_after = max(1, window_sec - max(0, now - min(arr)))
            RATE_LIMIT_STATE[idx] = arr
            return False, retry_after
        arr.append(now)
        RATE_LIMIT_STATE[idx] = arr
    return True, 0


def login_lock_status(ip: str):
    if not ip:
        return False, 0
    now = now_ts()
    with LOGIN_FAIL_LOCK:
        rec = LOGIN_FAIL_STATE.get(ip) or {}
        lock_until = int(rec.get("lock_until", 0) or 0)
        if lock_until > now:
            return True, lock_until - now
        if lock_until and lock_until <= now:
            LOGIN_FAIL_STATE.pop(ip, None)
    return False, 0


def login_record_failure(ip: str):
    if not ip:
        return
    now = now_ts()
    with LOGIN_FAIL_LOCK:
        rec = LOGIN_FAIL_STATE.get(ip) or {"fails": 0, "lock_until": 0}
        fails = int(rec.get("fails", 0)) + 1
        lock_until = int(rec.get("lock_until", 0) or 0)
        if fails >= LOGIN_LOCK_FAIL_THRESHOLD:
            lock_until = now + LOGIN_LOCK_DURATION_SEC
            fails = 0
        LOGIN_FAIL_STATE[ip] = {"fails": fails, "lock_until": lock_until}


def login_record_success(ip: str):
    if not ip:
        return
    with LOGIN_FAIL_LOCK:
        LOGIN_FAIL_STATE.pop(ip, None)


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT_DIR), **kwargs)

    def log_message(self, fmt, *args):
        super().log_message(fmt, *args)

    def end_headers(self):
        # Prevent stale cached app files from serving old UI/state logic.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if self.is_secure_request():
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # On deploy revision change, ask browser to clear HTTP cache.
        req_path = urlparse(self.path).path
        if req_path in ("/", f"/{INDEX_FILE}"):
            prev_rev = self.get_cookie_value("app_rev") or ""
            if APP_REV and prev_rev != APP_REV:
                self.send_header("Clear-Site-Data", "\"cache\"")
                self.send_header("Set-Cookie", f"app_rev={APP_REV}; Path=/; SameSite=Lax; Max-Age=31536000")
        super().end_headers()

    def end_json(self, status: int, payload: dict, extra_headers=None):
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        use_gzip = False
        accept_encoding = self.headers.get("Accept-Encoding", "")
        if len(raw) > 2048 and "gzip" in accept_encoding.lower():
            use_gzip = True
        body = gzip.compress(raw, compresslevel=5) if use_gzip else raw
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
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

    def is_secure_request(self):
        proto = str(self.headers.get("X-Forwarded-Proto", "")).split(",")[0].strip().lower()
        if proto in {"https", "wss"}:
            return True
        host = str(self.headers.get("Host", "")).lower()
        if host.startswith("localhost:") or host.startswith("127.0.0.1:"):
            return False
        return False

    def should_secure_cookie(self):
        if COOKIE_SECURE_MODE in {"1", "true", "yes", "on"}:
            return True
        if COOKIE_SECURE_MODE in {"0", "false", "no", "off"}:
            return False
        return self.is_secure_request()

    def expected_origin_prefix(self):
        host = str(self.headers.get("Host", "")).strip()
        if not host:
            return ""
        scheme = "https" if self.is_secure_request() else "http"
        return f"{scheme}://{host}"

    def has_valid_same_origin(self):
        expected = self.expected_origin_prefix()
        if not expected:
            return True
        origin = str(self.headers.get("Origin", "")).strip()
        referer = str(self.headers.get("Referer", "")).strip()
        if not origin and not referer:
            return True
        if origin and origin.rstrip("/") == expected.rstrip("/"):
            return True
        if referer and referer.startswith(expected):
            return True
        return False

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
        if self.should_secure_cookie():
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
        if self.should_secure_cookie():
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
        if path == "/api/viewer-email-export":
            if not self.is_admin_session():
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "admin required"})
                return
            data = read_viewer_email_data()
            entries = data.get("entries", [])
            unique_emails = []
            seen = set()
            for e in entries:
                email = str(e.get("email", "")).strip().lower()
                if email and email not in seen:
                    seen.add(email)
                    unique_emails.append(email)
            self.end_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "count": len(entries),
                    "uniqueCount": len(unique_emails),
                    "uniqueEmails": unique_emails,
                    "entries": entries,
                },
            )
            return
        if path == "/api/storage-health":
            if not self.is_admin_session():
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "admin required"})
                return
            email_data = read_viewer_email_data()
            email_entries = email_data.get("entries", [])
            email_by_ip = email_data.get("byIp", {})
            state_payload = read_state_lite_payload() or read_state_payload()
            state_obj = state_payload.get("state", {}) if isinstance(state_payload, dict) else {}
            strikes = state_obj.get("strikes", []) if isinstance(state_obj, dict) else []
            strike_reports = read_strike_reports(limit=MAX_STRIKE_REPORTS)
            pending_reports = [x for x in strike_reports if str(x.get("status", "pending")) == "pending"]
            viewer_email_file = str(VIEWER_EMAIL_FILE)
            state_file = str(STATE_FILE)
            strike_reports_file = str(STRIKE_REPORTS_FILE)
            self.end_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "viewerEmailFile": viewer_email_file,
                    "viewerEmailPersistent": viewer_email_file.startswith("/var/data/"),
                    "viewerEmailEntryCount": len(email_entries) if isinstance(email_entries, list) else 0,
                    "viewerEmailIpCount": len(email_by_ip) if isinstance(email_by_ip, dict) else 0,
                    "stateFile": state_file,
                    "statePersistent": state_file.startswith("/var/data/"),
                    "strikeCount": len(strikes) if isinstance(strikes, list) else 0,
                    "strikeReportsFile": strike_reports_file,
                    "strikeReportsPersistent": strike_reports_file.startswith("/var/data/"),
                    "strikeReportsCount": len(strike_reports),
                    "strikeReportsPendingCount": len(pending_reports),
                },
            )
            return
        if path == "/api/state":
            q = parse_qs(parsed.query or "")
            lite = str(q.get("lite", ["0"])[0]).lower() in {"1", "true", "yes"}
            payload = read_state_lite_payload() if lite else read_state_payload()
            if payload is None and lite:
                full = read_state_payload()
                payload = make_lite_state_payload(full) if isinstance(full, dict) else None
            if payload is None:
                self.end_json(HTTPStatus.OK, {"ok": True, "state": None})
            else:
                self.end_json(HTTPStatus.OK, payload)
            return
        if path == "/api/strike-images":
            q = parse_qs(parsed.query or "")
            strike_id = str(q.get("id", [""])[0]).strip()
            if not strike_id:
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "id required"})
                return
            payload = read_state_payload()
            state = payload.get("state", {}) if isinstance(payload, dict) else {}
            strikes = state.get("strikes", []) if isinstance(state, dict) else []
            for s in strikes:
                if not isinstance(s, dict):
                    continue
                if str(s.get("id", "")) != strike_id:
                    continue
                imgs = s.get("images")
                images = []
                if isinstance(imgs, list):
                    for x in imgs:
                        if not isinstance(x, str):
                            continue
                        sx = x.strip()
                        if not sx:
                            continue
                        if sx.startswith("data:image/") or sx.startswith("blob:") or sx.startswith("/") or sx.startswith("./") or sx.startswith("../") or re.match(r"^https?://", sx, re.I):
                            images.append(sx)
                self.end_json(HTTPStatus.OK, {"ok": True, "id": strike_id, "images": images, "count": len(images)})
                return
            self.end_json(HTTPStatus.NOT_FOUND, {"error": "strike not found"})
            return
        if path == "/api/x-recent-reports":
            q = parse_qs(parsed.query or "")
            query = str(q.get("query", [""])[0]).strip()
            if not query:
                query = (
                    "(missile OR strike OR airstrike OR explosion OR drone OR bombardment) "
                    "(Iran OR Israel OR Lebanon OR Iraq OR Syria OR Gaza OR Hezbollah)"
                )
            try:
                limit = int(q.get("limit", ["20"])[0])
            except ValueError:
                limit = 20
            limit = max(5, min(limit, 50))
            try:
                reports = fetch_x_recent_reports(query, limit)
            except ValueError as exc:
                self.end_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return
            except TimeoutError:
                self.end_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": "x api request timed out"})
                return
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"x api request failed: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "reports": reports, "query": query})
            return
        if path == "/api/gdelt-reports":
            q = parse_qs(parsed.query or "")
            query = str(q.get("query", [""])[0]).strip() or "Middle East missile strike airstrike drone attack"
            try:
                limit = int(q.get("limit", ["20"])[0])
            except ValueError:
                limit = 20
            limit = max(5, min(limit, 100))
            try:
                reports = fetch_gdelt_reports(query, limit)
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"gdelt request failed: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "reports": reports, "query": query, "source": "gdelt"})
            return
        if path == "/api/reliefweb-reports":
            q = parse_qs(parsed.query or "")
            query = str(q.get("query", [""])[0]).strip() or "Middle East conflict strike military action"
            try:
                limit = int(q.get("limit", ["20"])[0])
            except ValueError:
                limit = 20
            limit = max(5, min(limit, 100))
            try:
                reports = fetch_reliefweb_reports(query, limit)
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"reliefweb request failed: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "reports": reports, "query": query, "source": "reliefweb"})
            return
        if path == "/api/telegram-reports":
            q = parse_qs(parsed.query or "")
            query = str(q.get("query", [""])[0]).strip()
            channels_csv = str(q.get("channels", [""])[0]).strip()
            channels = [x.strip().lstrip("@") for x in channels_csv.split(",") if x.strip()] if channels_csv else TELEGRAM_CHANNELS
            try:
                limit = int(q.get("limit", ["20"])[0])
            except ValueError:
                limit = 20
            limit = max(5, min(limit, 100))
            try:
                reports = fetch_telegram_reports(channels, limit, query=query)
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"telegram scrape failed: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "reports": reports, "query": query, "source": "telegram", "channels": channels})
            return
        if path == "/api/free-sources-reports":
            q = parse_qs(parsed.query or "")
            query = str(q.get("query", [""])[0]).strip() or "Middle East conflict strike military action"
            channels_csv = str(q.get("channels", [""])[0]).strip()
            channels = [x.strip().lstrip("@") for x in channels_csv.split(",") if x.strip()] if channels_csv else TELEGRAM_CHANNELS
            try:
                limit = int(q.get("limit", ["40"])[0])
            except ValueError:
                limit = 40
            limit = max(10, min(limit, 200))
            try:
                reports = fetch_free_sources_reports(query, channels, limit)
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"free-source import failed: {exc}"})
                return
            self.end_json(
                HTTPStatus.OK,
                {"ok": True, "reports": reports, "query": query, "sources": ["gdelt", "reliefweb", "telegram"]},
            )
            return
        if path == "/api/manual-reports":
            q = parse_qs(parsed.query or "")
            try:
                limit = int(q.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            limit = max(1, min(limit, 500))
            reports = read_manual_reports(limit=limit)
            self.end_json(
                HTTPStatus.OK,
                {"ok": True, "reports": reports},
                extra_headers=manual_cors_headers(),
            )
            return
        if path == "/api/strike-reports":
            if not self.is_admin_session():
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "admin required"})
                return
            reports = read_strike_reports(limit=1000)
            self.end_json(HTTPStatus.OK, {"ok": True, "reports": reports})
            return

        if path in ("/", ""):
            self.path = "/" + INDEX_FILE
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        client_ip = self.get_client_ip() or "unknown"

        same_origin_required = {
            "/api/login",
            "/api/logout",
            "/api/state",
            "/api/viewer-email",
            "/api/strike-report",
            "/api/strike-reports-approve",
            "/api/strike-reports-reject",
        }
        if path in same_origin_required and not self.has_valid_same_origin():
            self.end_json(HTTPStatus.FORBIDDEN, {"error": "cross-origin write blocked"})
            return

        if path == "/api/login":
            ok, retry = rate_limit_check("login", client_ip, LOGIN_RATE_MAX_ATTEMPTS, LOGIN_RATE_WINDOW_SEC)
            if not ok:
                self.end_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "too many login attempts", "retryAfter": retry})
                return
            locked, remaining = login_lock_status(client_ip)
            if locked:
                self.end_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "login temporarily locked", "retryAfter": remaining})
                return
            body = self.read_json_body()
            username = str(body.get("username", "")).strip().lower()
            password = str(body.get("password", ""))
            valid_user = hmac.compare_digest(username, str(ADMIN_USERNAME).strip().lower())
            valid_pass = verify_admin_password(password)
            if not (valid_user and valid_pass):
                login_record_failure(client_ip)
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials"})
                return
            login_record_success(client_ip)
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
            # Hard safety ceiling to avoid service instability on oversized saves.
            absolute_limit = int(os.getenv("ABSOLUTE_MAX_STATE_BYTES", str(600 * 1024 * 1024)))
            if absolute_limit > 0 and content_length > absolute_limit:
                limit_mb = round(absolute_limit / (1024 * 1024), 2)
                self.end_json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": f"state too large (hard limit {limit_mb} MB)"},
                )
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
            allow_empty = bool(body.get("allowEmpty", False))
            incoming_strikes = state.get("strikes")
            incoming_count = len(incoming_strikes) if isinstance(incoming_strikes, list) else 0
            # Safety lock: avoid accidental wipe of live markers.
            if incoming_count == 0 and not allow_empty:
                self.end_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": "refusing to overwrite live state with 0 strikes; pass allowEmpty=true to force"
                    },
                )
                return
            preserved_reports = body.get("strikeReports", [])
            if not isinstance(preserved_reports, list):
                preserved_reports = read_strike_reports(limit=MAX_STRIKE_REPORTS)
            saved_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            payload = {
                "ok": True,
                "savedAt": saved_at,
                "state": state,
                "strikeReports": sanitize_strike_reports(preserved_reports, limit=MAX_STRIKE_REPORTS),
            }
            try:
                write_state_payload(payload)
            except Exception as exc:
                self.end_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"failed to save state: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "savedAt": saved_at})
            return
        if path == "/api/viewer-email":
            ok, retry = rate_limit_check("viewer-email", client_ip, VIEWER_EMAIL_RATE_MAX_ATTEMPTS, VIEWER_EMAIL_RATE_WINDOW_SEC)
            if not ok:
                self.end_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "too many submissions", "retryAfter": retry})
                return
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
        if path == "/api/detect-image-authenticity":
            body = self.read_json_body()
            image_url = str(body.get("imageUrl", "")).strip()
            if not is_valid_public_media_url(image_url):
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "imageUrl must be a valid http/https URL"})
                return
            try:
                result = detect_media_authenticity(image_url, media_type="image")
            except ValueError as exc:
                self.end_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return
            except TimeoutError:
                self.end_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": "detector request timed out"})
                return
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"detector request failed: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, **result})
            return
        if path == "/api/detect-media-authenticity":
            body = self.read_json_body()
            media_url = str(body.get("mediaUrl", "")).strip() or str(body.get("imageUrl", "")).strip()
            media_type = str(body.get("mediaType", "auto")).strip().lower() or "auto"
            if media_type not in {"auto", "image", "video"}:
                media_type = "auto"
            if not is_valid_public_media_url(media_url):
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "mediaUrl must be a valid http/https URL"})
                return
            try:
                result = detect_media_authenticity(media_url, media_type=media_type)
            except ValueError as exc:
                self.end_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return
            except TimeoutError:
                self.end_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": "detector request timed out"})
                return
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"detector request failed: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, **result})
            return
        if path == "/api/war-visual-relevance":
            body = self.read_json_body()
            media_url = str(body.get("mediaUrl", "")).strip()
            context_text = str(body.get("contextText", "")).strip()
            if not is_valid_public_media_url(media_url):
                self.end_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "mediaUrl must be a valid http/https URL"},
                    extra_headers=manual_cors_headers(),
                )
                return
            try:
                result = classify_war_visual_relevance(media_url, context_text=context_text)
            except ValueError as exc:
                self.end_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": str(exc)},
                    extra_headers=manual_cors_headers(),
                )
                return
            except TimeoutError:
                self.end_json(
                    HTTPStatus.GATEWAY_TIMEOUT,
                    {"error": "visual classifier timed out"},
                    extra_headers=manual_cors_headers(),
                )
                return
            except Exception as exc:
                self.end_json(
                    HTTPStatus.BAD_GATEWAY,
                    {"error": f"visual classifier failed: {exc}"},
                    extra_headers=manual_cors_headers(),
                )
                return
            self.end_json(HTTPStatus.OK, {"ok": True, **result}, extra_headers=manual_cors_headers())
            return
        if path == "/api/ai-triage-report":
            body = self.read_json_body()
            report = body.get("report") if isinstance(body, dict) else None
            if not isinstance(report, dict):
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "report object required"})
                return
            try:
                triage = ai_triage_report(report)
            except ValueError as exc:
                self.end_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return
            except TimeoutError:
                self.end_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": "ai triage timed out"})
                return
            except Exception as exc:
                self.end_json(HTTPStatus.BAD_GATEWAY, {"error": f"ai triage failed: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "triage": triage})
            return
        if path == "/api/manual-report":
            body = self.read_json_body()
            report = normalize_manual_report(body)
            if report is None:
                self.end_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid report payload"},
                    extra_headers=manual_cors_headers(),
                )
                return
            try:
                append_manual_report(report)
            except Exception as exc:
                self.end_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"failed to save manual report: {exc}"},
                    extra_headers=manual_cors_headers(),
                )
                return
            self.end_json(
                HTTPStatus.OK,
                {"ok": True, "id": report.get("id")},
                extra_headers=manual_cors_headers(),
            )
            return
        if path == "/api/strike-report":
            ok, retry = rate_limit_check("strike-report", client_ip, STRIKE_REPORT_RATE_MAX_ATTEMPTS, STRIKE_REPORT_RATE_WINDOW_SEC)
            if not ok:
                self.end_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "too many report submissions", "retryAfter": retry})
                return
            limits = get_strike_report_limits()
            raw_len = self.headers.get("Content-Length", "0")
            try:
                content_length = int(raw_len)
            except ValueError:
                content_length = 0
            if content_length <= 0:
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "missing request body"})
                return
            if content_length > int(limits.get("payload_max_bytes", 0)):
                self.end_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "strike report payload too large"})
                return
            body = self.read_json_body()
            report = normalize_strike_report(body, limits=limits)
            if report is None:
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "invalid strike report payload"})
                return
            try:
                append_strike_report(report)
            except Exception as exc:
                self.end_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"failed to save strike report: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "id": report.get("id")})
            return
        if path == "/api/strike-reports-approve":
            if not self.is_admin_session():
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "admin required"})
                return
            body = self.read_json_body()
            rid = str(body.get("id", "")).strip()
            if not rid:
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "id required"})
                return
            try:
                report = resolve_strike_report(rid, "approved")
            except KeyError:
                self.end_json(HTTPStatus.NOT_FOUND, {"error": "report not found"})
                return
            except Exception as exc:
                self.end_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"failed to approve report: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "report": report})
            return
        if path == "/api/strike-reports-reject":
            if not self.is_admin_session():
                self.end_json(HTTPStatus.UNAUTHORIZED, {"error": "admin required"})
                return
            body = self.read_json_body()
            rid = str(body.get("id", "")).strip()
            if not rid:
                self.end_json(HTTPStatus.BAD_REQUEST, {"error": "id required"})
                return
            try:
                report = resolve_strike_report(rid, "rejected")
            except KeyError:
                self.end_json(HTTPStatus.NOT_FOUND, {"error": "report not found"})
                return
            except Exception as exc:
                self.end_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"failed to reject report: {exc}"})
                return
            self.end_json(HTTPStatus.OK, {"ok": True, "report": report})
            return
        if path == "/api/manual-reports-clear":
            try:
                clear_manual_reports()
            except Exception as exc:
                self.end_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": f"failed to clear manual reports: {exc}"},
                    extra_headers=manual_cors_headers(),
                )
                return
            self.end_json(
                HTTPStatus.OK,
                {"ok": True, "cleared": True},
                extra_headers=manual_cors_headers(),
            )
            return

        self.end_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_OPTIONS(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in {"/api/manual-report", "/api/manual-reports", "/api/manual-reports-clear", "/api/war-visual-relevance", "/api/ai-triage-report", "/api/strike-report"}:
            self.send_response(HTTPStatus.NO_CONTENT)
            for k, v in manual_cors_headers().items():
                self.send_header(k, v)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()


def read_state_payload():
    try:
        for p in (STATE_FILE, STATE_BACKUP_FILE):
            if not p.exists():
                continue
            raw = p.read_text(encoding="utf-8")
            if not raw.strip():
                continue
            data = json.loads(raw)
            if not isinstance(data, dict):
                continue
            state = data.get("state")
            if not isinstance(state, dict):
                continue
            out = {
                "ok": True,
                "savedAt": data.get("savedAt"),
                "state": state,
            }
            strike_reports = data.get("strikeReports")
            if isinstance(strike_reports, list):
                out["strikeReports"] = sanitize_strike_reports(strike_reports, limit=MAX_STRIKE_REPORTS)
            return out
        return None
    except Exception:
        return None


def read_state_lite_payload():
    try:
        if not STATE_LITE_FILE.exists():
            return None
        raw = STATE_LITE_FILE.read_text(encoding="utf-8")
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
            "lite": True,
        }
    except Exception:
        return None


def write_state_payload(payload: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_LITE_FILE.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, separators=(",", ":"))
    lite_payload = make_lite_state_payload(payload) if isinstance(payload, dict) else None
    lite_body = json.dumps(lite_payload, separators=(",", ":")) if isinstance(lite_payload, dict) else ""
    with STATE_WRITE_LOCK:
        # Unique temp names prevent collisions across threaded concurrent writes.
        tmp = STATE_FILE.with_suffix(STATE_FILE.suffix + f".{secrets.token_hex(6)}.tmp")
        tmp.write_text(body, encoding="utf-8")
        tmp.replace(STATE_FILE)
        # Keep a dedicated lite snapshot for fast viewer polling/loading.
        if lite_body:
            lite_tmp = STATE_LITE_FILE.with_suffix(STATE_LITE_FILE.suffix + f".{secrets.token_hex(6)}.tmp")
            lite_tmp.write_text(lite_body, encoding="utf-8")
            lite_tmp.replace(STATE_LITE_FILE)
        # Backup snapshots are useful, but writing them every autosave is expensive.
        should_write_backup = True
        try:
            if STATE_BACKUP_FILE.exists():
                age = time.time() - STATE_BACKUP_FILE.stat().st_mtime
                should_write_backup = age > 300
        except Exception:
            should_write_backup = True
        if should_write_backup:
            bak_tmp = STATE_BACKUP_FILE.with_suffix(STATE_BACKUP_FILE.suffix + f".{secrets.token_hex(6)}.tmp")
            bak_tmp.write_text(body, encoding="utf-8")
            bak_tmp.replace(STATE_BACKUP_FILE)


def make_lite_state_payload(payload: dict) -> dict:
    state = payload.get("state")
    if not isinstance(state, dict):
        return payload
    strikes = state.get("strikes")
    if not isinstance(strikes, list):
        return payload
    lite_strikes = []
    for s in strikes:
        if not isinstance(s, dict):
            continue
        item = dict(s)
        imgs = item.get("images")
        item["imageCount"] = len(imgs) if isinstance(imgs, list) else 0
        item["images"] = []
        lite_strikes.append(item)
    lite_state = dict(state)
    lite_state["strikes"] = lite_strikes
    out = dict(payload)
    out["state"] = lite_state
    out["lite"] = True
    return out


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


def manual_cors_headers() -> dict:
    return {"Access-Control-Allow-Origin": "*"}


def extract_x_handle_from_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return ""
    host = (parsed.netloc or "").lower()
    if "x.com" not in host and "twitter.com" not in host:
        return ""
    parts = [p for p in (parsed.path or "").split("/") if p]
    if not parts:
        return ""
    handle = parts[0].strip()
    if handle.startswith("@"):
        handle = handle[1:]
    if not handle or handle.lower() in {"i", "home", "explore", "search"}:
        return ""
    return handle


def infer_actor_region_city(text: str) -> tuple:
    t = (text or "").lower()

    actor = "Unknown"
    actor_keywords = [
        ("iran", "Iran"),
        ("israel", "Israel"),
        ("hezbollah", "Hezbollah"),
        ("hamas", "Hamas"),
        ("saudi", "Saudi Arabia"),
        ("uae", "UAE"),
        ("us", "United States"),
        ("u.s.", "United States"),
    ]
    for key, label in actor_keywords:
        if key in t:
            actor = label
            break

    region = "Unknown"
    city = "Unknown"
    location_keywords = [
        ("tehran", ("Iran", "Tehran")),
        ("mehrabad", ("Iran", "Tehran")),
        ("bushehr", ("Iran", "Bushehr")),
        ("beersheba", ("Israel", "Beersheba")),
        ("beer sheva", ("Israel", "Beersheba")),
        ("tel aviv", ("Israel", "Tel Aviv")),
        ("haifa", ("Israel", "Haifa")),
        ("tyre", ("Lebanon", "Tyre")),
        ("beirut", ("Lebanon", "Beirut")),
        ("erbil", ("Iraq", "Erbil")),
        ("baghdad", ("Iraq", "Baghdad")),
        ("doha", ("Qatar", "Doha")),
        ("manama", ("Bahrain", "Manama")),
        ("muscat", ("Oman", "Muscat")),
        ("abu dhabi", ("UAE", "Abu Dhabi")),
        ("dubai", ("UAE", "Dubai")),
        ("riyadh", ("Saudi Arabia", "Riyadh")),
    ]
    for key, loc in location_keywords:
        if key in t:
            region, city = loc
            break

    return actor, region, city


def normalize_manual_report(payload: dict):
    if not isinstance(payload, dict):
        return None
    url = str(payload.get("url", "")).strip()
    title = str(payload.get("title", "")).strip()
    text = str(payload.get("text", "")).strip()
    source = str(payload.get("source", "")).strip() or "Manual clip"
    language = str(payload.get("language", "")).strip() or "und"
    image_url = str(payload.get("imageUrl", "")).strip()
    video_url = str(payload.get("videoUrl", "")).strip()
    if not url and not text:
        return None
    if not title:
        title = text[:140] + ("..." if len(text) > 140 else "")
    if not text:
        text = title
    handle = extract_x_handle_from_url(url)
    if handle:
        source = f"@{handle}"

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    clip_id = str(payload.get("id", "")).strip()
    if not clip_id:
        # Deterministic ID by permalink so duplicate clips collapse server-side.
        base = url if url else f"{title}|{text}"
        clip_id = "manual-" + hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]

    incident_type = detect_incident_type(text)
    actor, region, city = infer_actor_region_city(text)
    preview = text if len(text) <= 220 else text[:217] + "..."

    return {
        "id": clip_id,
        "source": source,
        "platform": "X-Clipper",
        "language": language,
        "region": region,
        "city": city,
        "actor": actor,
        "target": "Unknown",
        "incidentType": incident_type,
        "reportedAt": str(payload.get("reportedAt", "")).strip() or now_iso,
        "title": title,
        "url": url,
        "imageUrl": image_url if is_valid_public_image_url(image_url) else "",
        "videoUrl": video_url if is_valid_public_media_url(video_url) else "",
        "mediaType": "video" if is_valid_public_media_url(video_url) else ("image" if is_valid_public_image_url(image_url) else "unknown"),
        "preview": preview,
        "summary": "Imported from personal X clipper. Content requires independent verification.",
        "aiImageRisk": "Unclear",
        "importedAt": int(time.time()),
    }


def read_manual_reports(limit: int = 100) -> list:
    try:
        if not MANUAL_REPORTS_FILE.exists():
            return []
        raw = MANUAL_REPORTS_FILE.read_text(encoding="utf-8")
        if not raw.strip():
            return []
        data = json.loads(raw)
        if not isinstance(data, list):
            return []
        items = [x for x in data if isinstance(x, dict)]
        items.sort(key=lambda x: int(x.get("importedAt", 0)), reverse=True)
        return items[:limit]
    except Exception:
        return []


def append_manual_report(report: dict):
    MANUAL_REPORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = read_manual_reports(limit=5000)
    by_id = {str(x.get("id")): x for x in existing if x.get("id")}
    by_id[str(report.get("id"))] = report
    merged = list(by_id.values())
    merged.sort(key=lambda x: int(x.get("importedAt", 0)))
    if len(merged) > 5000:
        merged = merged[-5000:]
    tmp = MANUAL_REPORTS_FILE.with_suffix(MANUAL_REPORTS_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(merged, separators=(",", ":")), encoding="utf-8")
    tmp.replace(MANUAL_REPORTS_FILE)


def clear_manual_reports():
    MANUAL_REPORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = MANUAL_REPORTS_FILE.with_suffix(MANUAL_REPORTS_FILE.suffix + ".tmp")
    tmp.write_text("[]", encoding="utf-8")
    tmp.replace(MANUAL_REPORTS_FILE)


def sanitize_strike_reports(items, limit: int = MAX_STRIKE_REPORTS) -> list:
    if not isinstance(items, list):
        return []
    out = []
    seen = set()
    for x in items:
        if not isinstance(x, dict):
            continue
        rid = str(x.get("id", "")).strip()
        if not rid or rid in seen:
            continue
        seen.add(rid)
        item = dict(x)
        item["id"] = rid
        try:
            item["createdAtTs"] = int(item.get("createdAtTs", 0))
        except Exception:
            item["createdAtTs"] = 0
        status = str(item.get("status", "pending")).strip().lower()
        item["status"] = status if status in {"pending", "approved", "rejected"} else "pending"
        out.append(item)
    out.sort(key=lambda x: int(x.get("createdAtTs", 0)), reverse=True)
    if limit > 0 and len(out) > limit:
        out = out[:limit]
    return out


def estimate_data_url_bytes(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("data:image/"):
        return 0
    comma = value.find(",")
    if comma < 0:
        return 0
    meta = value[:comma].lower()
    payload = value[comma + 1 :]
    if ";base64" in meta:
        n = len(payload.strip())
        pad = 0
        if payload.endswith("=="):
            pad = 2
        elif payload.endswith("="):
            pad = 1
        return max(0, ((n * 3) // 4) - pad)
    return len(payload.encode("utf-8"))


def get_max_live_strike_image_bytes() -> int:
    payload = read_state_payload()
    if not isinstance(payload, dict):
        return 0
    state = payload.get("state")
    if not isinstance(state, dict):
        return 0
    strikes = state.get("strikes")
    if not isinstance(strikes, list):
        return 0
    max_bytes = 0
    for s in strikes:
        if not isinstance(s, dict):
            continue
        images = s.get("images")
        if not isinstance(images, list):
            continue
        for img in images:
            if not isinstance(img, str):
                continue
            size = estimate_data_url_bytes(img)
            if size > max_bytes:
                max_bytes = size
    return max_bytes


def get_strike_report_limits() -> dict:
    max_live = get_max_live_strike_image_bytes()
    dynamic_cap = max_live + STRIKE_REPORT_IMAGE_MARGIN_BYTES
    image_cap = max(STRIKE_REPORT_MIN_IMAGE_BYTES, dynamic_cap)
    image_cap = min(image_cap, STRIKE_REPORT_MAX_IMAGE_BYTES)
    payload_cap = image_cap + STRIKE_REPORT_MAX_PAYLOAD_OVERHEAD
    return {
        "notes_max": max(1, STRIKE_REPORT_NOTES_MAX_CHARS),
        "title_max": max(20, STRIKE_REPORT_TITLE_MAX_CHARS),
        "max_images": 1,
        "image_max_bytes": max(64 * 1024, image_cap),
        "payload_max_bytes": max(128 * 1024, payload_cap),
    }


def _read_strike_reports_from_file() -> list:
    if not STRIKE_REPORTS_FILE.exists():
        return []
    raw = STRIKE_REPORTS_FILE.read_text(encoding="utf-8")
    if not raw.strip():
        return []
    data = json.loads(raw)
    return sanitize_strike_reports(data, limit=MAX_STRIKE_REPORTS)


def _read_embedded_strike_reports() -> list:
    payload = read_state_payload()
    if not isinstance(payload, dict):
        return []
    return sanitize_strike_reports(payload.get("strikeReports", []), limit=MAX_STRIKE_REPORTS)


def read_strike_reports(limit: int = 1000) -> list:
    try:
        by_id = {}
        for item in _read_embedded_strike_reports():
            by_id[str(item.get("id"))] = item
        for item in _read_strike_reports_from_file():
            rid = str(item.get("id"))
            cur = by_id.get(rid)
            if cur is None:
                by_id[rid] = item
                continue
            if int(item.get("createdAtTs", 0)) >= int(cur.get("createdAtTs", 0)):
                by_id[rid] = item
        items = list(by_id.values())
        items.sort(key=lambda x: int(x.get("createdAtTs", 0)), reverse=True)
        if limit > 0:
            return items[:limit]
        return items
    except Exception:
        return []


def write_strike_reports(items: list):
    normalized = sanitize_strike_reports(items, limit=MAX_STRIKE_REPORTS)
    STRIKE_REPORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STRIKE_REPORTS_FILE.with_suffix(STRIKE_REPORTS_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(normalized, separators=(",", ":")), encoding="utf-8")
    tmp.replace(STRIKE_REPORTS_FILE)
    # Mirror strike reports into the live state payload so regular state saves do not drop them.
    state_payload = read_state_payload()
    if isinstance(state_payload, dict) and isinstance(state_payload.get("state"), dict):
        mirrored = dict(state_payload)
        mirrored["strikeReports"] = normalized
        write_state_payload(mirrored)


def normalize_strike_report(payload: dict, limits: dict = None):
    if not isinstance(payload, dict):
        return None
    lim = limits or get_strike_report_limits()
    try:
        lat = float(payload.get("lat"))
        lng = float(payload.get("lng"))
    except Exception:
        return None
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return None
    title = str(payload.get("title", "")).strip()
    notes = str(payload.get("notes", "")).strip()
    source_url = str(payload.get("sourceUrl", "")).strip()
    event_date = str(payload.get("eventDate", "")).strip()
    color = str(payload.get("color", "")).strip().lower()
    icon = str(payload.get("icon", "")).strip()
    if not title or not notes:
        return None
    if len(notes) > int(lim.get("notes_max", STRIKE_REPORT_NOTES_MAX_CHARS)):
        return None
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", event_date):
        return None
    if not re.match(r"^#([0-9a-f]{3}|[0-9a-f]{6})$", color):
        return None
    if icon not in {"rocket", "ak47", "target", "naval"}:
        return None
    if source_url:
        parts = urlparse(source_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            return None
    images_in = payload.get("images")
    if not isinstance(images_in, list):
        return None
    if len(images_in) != int(lim.get("max_images", 1)):
        return None
    images = [str(x) for x in images_in if isinstance(x, str) and x.startswith("data:image/")]
    if len(images) != int(lim.get("max_images", 1)):
        return None
    max_img_bytes = int(lim.get("image_max_bytes", STRIKE_REPORT_MAX_IMAGE_BYTES))
    for img in images:
        if estimate_data_url_bytes(img) > max_img_bytes:
            return None
    rid = str(payload.get("id", "")).strip() or f"strike-report-{secrets.token_hex(8)}"
    created_at = str(payload.get("createdAt", "")).strip() or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "id": rid,
        "status": "pending",
        "lat": round(lat, 6),
        "lng": round(lng, 6),
        "color": color,
        "icon": icon,
        "title": title[: int(lim.get("title_max", STRIKE_REPORT_TITLE_MAX_CHARS))],
        "sourceUrl": source_url[:1000],
        "notes": notes[: int(lim.get("notes_max", STRIKE_REPORT_NOTES_MAX_CHARS))],
        "eventDate": event_date,
        "images": images[: int(lim.get("max_images", 1))],
        "createdAt": created_at,
        "submittedAt": now_iso,
        "createdAtTs": int(time.time()),
        "resolvedAt": "",
    }


def append_strike_report(report: dict):
    existing = read_strike_reports(limit=MAX_STRIKE_REPORTS)
    by_id = {str(x.get("id")): x for x in existing if x.get("id")}
    by_id[str(report.get("id"))] = report
    merged = list(by_id.values())
    merged.sort(key=lambda x: int(x.get("createdAtTs", 0)))
    if len(merged) > MAX_STRIKE_REPORTS:
        merged = merged[-MAX_STRIKE_REPORTS:]
    write_strike_reports(merged)


def resolve_strike_report(report_id: str, status: str):
    items = read_strike_reports(limit=MAX_STRIKE_REPORTS)
    found = None
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    for it in items:
        if str(it.get("id")) != str(report_id):
            continue
        it["status"] = status
        it["resolvedAt"] = now_iso
        found = it
        break
    if found is None:
        raise KeyError(report_id)
    write_strike_reports(items)
    return found


def is_valid_public_image_url(value: str) -> bool:
    if not value or len(value) > 2048:
        return False
    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    return bool(parsed.netloc)


def is_valid_public_media_url(value: str) -> bool:
    return is_valid_public_image_url(value)


def classify_ai_probability(score: float) -> str:
    if score >= 0.75:
        return "Likely AI-generated"
    if score <= 0.25:
        return "Likely authentic"
    return "Unclear"


def detect_image_authenticity(image_url: str) -> dict:
    if AI_IMAGE_DETECT_PROVIDER != "sightengine":
        raise ValueError("unsupported detector provider; set AI_IMAGE_DETECT_PROVIDER=sightengine")
    if not SIGHTENGINE_API_USER or not SIGHTENGINE_API_SECRET:
        raise ValueError("detector not configured; set SIGHTENGINE_API_USER and SIGHTENGINE_API_SECRET")

    query = urllib.parse.urlencode(
        {
            "models": "genai",
            "url": image_url,
            "api_user": SIGHTENGINE_API_USER,
            "api_secret": SIGHTENGINE_API_SECRET,
        }
    )
    endpoint = f"https://api.sightengine.com/1.0/check.json?{query}"
    req = urllib.request.Request(endpoint, headers={"User-Agent": "codex-conflict-monitor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=AI_DETECT_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise TimeoutError("timeout") from exc
        raise

    try:
        data = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"detector response parse error: {exc}") from exc
    type_obj = data.get("type", {})
    ai_score = None
    if isinstance(type_obj, dict):
        for key in ("ai_generated", "deepfake", "synthetic"):
            value = type_obj.get(key)
            if isinstance(value, (int, float)):
                ai_score = max(float(value), float(ai_score)) if ai_score is not None else float(value)

    if ai_score is None:
        raise ValueError("detector response missing AI probability score")

    label = classify_ai_probability(ai_score)
    return {
        "provider": "sightengine",
        "score": round(ai_score, 4),
        "label": label,
    }


def detect_media_authenticity(media_url: str, media_type: str = "auto") -> dict:
    # Sightengine's URL check endpoint supports both images and videos via URL input.
    base = detect_image_authenticity(media_url)
    base["mediaType"] = media_type if media_type in {"image", "video"} else "auto"
    return base


def _extract_first_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return ""
    return text[start : end + 1]


def classify_war_visual_relevance(media_url: str, context_text: str = "") -> dict:
    if not OPENAI_API_KEY:
        raise ValueError("visual classifier not configured; set OPENAI_API_KEY")
    if not is_valid_public_media_url(media_url):
        raise ValueError("mediaUrl must be a valid http/https URL")

    system_prompt = (
        "You are a strict media relevance classifier for conflict monitoring. "
        "Decide whether media visually depicts direct military action or strike aftermath. "
        "Strong positives: missile/drone launch or impact, explosions, artillery fire, warplanes in attack context, "
        "armored assault, dense impact smoke, damaged buildings from conflict. "
        "Return compact JSON only: {\"relevant\":bool,\"score\":0..1,\"signals\":[...],\"summary\":\"...\"}."
    )
    user_text = (
        "Classify this media for direct strike/military-action relevance. "
        f"Context text: {context_text[:1000] if context_text else 'none'}"
    )
    payload = {
        "model": OPENAI_VISION_MODEL,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": user_text},
                    {"type": "input_image", "image_url": media_url},
                ],
            },
        ],
        "max_output_tokens": 220,
    }

    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "codex-conflict-monitor/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        raise ValueError(f"openai http {exc.code}: {detail[:300]}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise TimeoutError("timeout") from exc
        raise

    data = json.loads(raw)
    output_text = ""
    if isinstance(data.get("output_text"), str):
        output_text = data.get("output_text", "")
    if not output_text:
        out = data.get("output", [])
        if isinstance(out, list):
            for item in out:
                content = item.get("content", []) if isinstance(item, dict) else []
                if not isinstance(content, list):
                    continue
                for c in content:
                    if isinstance(c, dict) and isinstance(c.get("text"), str):
                        output_text += c["text"]
    if not output_text:
        raise ValueError("openai returned empty classification output")

    obj_text = _extract_first_json_object(output_text)
    if not obj_text:
        raise ValueError("openai output missing JSON object")
    parsed = json.loads(obj_text)

    relevant = bool(parsed.get("relevant", False))
    score = parsed.get("score", 0.0)
    try:
        score = float(score)
    except Exception:
        score = 0.0
    score = max(0.0, min(1.0, score))
    signals = parsed.get("signals", [])
    if not isinstance(signals, list):
        signals = []
    signals = [str(x)[:80] for x in signals][:5]
    summary = str(parsed.get("summary", "")).strip()[:240]
    return {
        "provider": "openai",
        "model": OPENAI_VISION_MODEL,
        "relevant": relevant,
        "score": round(score, 4),
        "signals": signals,
        "summary": summary,
    }


def detect_incident_type(text: str) -> str:
    t = (text or "").lower()
    if any(k in t for k in ("drone", "uav")):
        return "drone attack"
    if any(k in t for k in ("missile", "rocket", "ballistic")):
        return "missile strike"
    if any(k in t for k in ("airstrike", "air strike", "strike", "bombing", "explosion")):
        return "airstrike"
    return "conflict report"


def heuristic_triage_report(report: dict) -> dict:
    title = str(report.get("title", "")).strip()
    preview = str(report.get("preview", "")).strip()
    text = f"{title} {preview}".strip()
    actor, region, city = infer_actor_region_city(text)
    incident_type = detect_incident_type(text)
    relevant = incident_type != "conflict report"
    score = 0.72 if relevant else 0.35
    loc = city if city != "Unknown" else (region if region != "Unknown" else "Unspecified location")
    headline = f"{actor if actor != 'Unknown' else 'Unattributed'} {incident_type} near {loc}"
    summary = (preview or title or "Imported conflict-related report.").strip()
    fp_base = f"{actor}|{region}|{city}|{incident_type}|{headline}".lower()
    fingerprint = hashlib.sha1(fp_base.encode("utf-8")).hexdigest()[:16]
    return {
        "relevant": relevant,
        "relevanceScore": round(score, 4),
        "actor": actor,
        "region": region,
        "city": city,
        "incidentType": incident_type,
        "headline": headline,
        "shortSummary": summary[:220],
        "incidentFingerprint": fingerprint,
        "confidence": round(score, 4),
        "provider": "heuristic",
    }


def ai_triage_report(report: dict) -> dict:
    if not isinstance(report, dict):
        raise ValueError("invalid report payload")
    title = str(report.get("title", "")).strip()
    preview = str(report.get("preview", "")).strip()
    summary = str(report.get("summary", "")).strip()
    source = str(report.get("source", "")).strip()
    language = str(report.get("language", "und")).strip() or "und"

    if not OPENAI_API_KEY:
        return heuristic_triage_report(report)

    system_prompt = (
        "You are an operations copilot for a conflict incident monitor. "
        "Classify one report and return JSON only with keys: "
        "relevant (bool), relevanceScore (0..1), actor (string), region (string), city (string), "
        "incidentType (one of: missile strike, airstrike, drone attack, naval strike, explosion event, conflict report), "
        "headline (specific concise incident headline), shortSummary (1 sentence), "
        "incidentFingerprint (stable grouping key text), confidence (0..1). "
        "Avoid Unknown unless truly absent."
    )
    user_prompt = (
        f"Source: {source}\n"
        f"Language: {language}\n"
        f"Title: {title}\n"
        f"Preview: {preview}\n"
        f"Summary: {summary}\n"
    )

    payload = {
        "model": OPENAI_VISION_MODEL,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
            {"role": "user", "content": [{"type": "input_text", "text": user_prompt}]},
        ],
        "max_output_tokens": 300,
    }

    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "codex-conflict-monitor/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        raise ValueError(f"openai http {exc.code}: {detail[:300]}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise TimeoutError("timeout") from exc
        raise

    data = json.loads(raw)
    output_text = data.get("output_text", "") if isinstance(data.get("output_text"), str) else ""
    if not output_text:
        out = data.get("output", [])
        if isinstance(out, list):
            for item in out:
                content = item.get("content", []) if isinstance(item, dict) else []
                if not isinstance(content, list):
                    continue
                for c in content:
                    if isinstance(c, dict) and isinstance(c.get("text"), str):
                        output_text += c["text"]
    obj_text = _extract_first_json_object(output_text)
    if not obj_text:
        return heuristic_triage_report(report)

    parsed = json.loads(obj_text)
    base = heuristic_triage_report(report)

    def _f(name, default=""):
        v = parsed.get(name, default)
        return str(v).strip() if v is not None else default

    def _score(name, default):
        v = parsed.get(name, default)
        try:
            v = float(v)
        except Exception:
            v = default
        return max(0.0, min(1.0, v))

    incident_type = _f("incidentType", base["incidentType"]).lower()
    if incident_type not in {"missile strike", "airstrike", "drone attack", "naval strike", "explosion event", "conflict report"}:
        incident_type = base["incidentType"]

    relevant = bool(parsed.get("relevant", base["relevant"]))
    triage = {
        "relevant": relevant,
        "relevanceScore": round(_score("relevanceScore", base["relevanceScore"]), 4),
        "actor": _f("actor", base["actor"]) or base["actor"],
        "region": _f("region", base["region"]) or base["region"],
        "city": _f("city", base["city"]) or base["city"],
        "incidentType": incident_type,
        "headline": _f("headline", base["headline"])[:180] or base["headline"],
        "shortSummary": _f("shortSummary", base["shortSummary"])[:240] or base["shortSummary"],
        "incidentFingerprint": _f("incidentFingerprint", base["incidentFingerprint"])[:120] or base["incidentFingerprint"],
        "confidence": round(_score("confidence", base["confidence"]), 4),
        "provider": "openai",
    }
    return triage


def fetch_x_recent_reports(query: str, limit: int) -> list:
    if not X_BEARER_TOKEN:
        raise ValueError("x api not configured; set X_BEARER_TOKEN")

    params = urllib.parse.urlencode(
        {
            "query": query,
            "max_results": str(limit),
            "tweet.fields": "created_at,lang,author_id",
            "expansions": "author_id",
            "user.fields": "username,name,verified",
        }
    )
    endpoint = f"{X_API_BASE_URL}/2/tweets/search/recent?{params}"
    req = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {X_BEARER_TOKEN}",
            "User-Agent": "codex-conflict-monitor/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=X_API_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        msg = f"http {exc.code}"
        if detail:
            msg += f" - {detail[:500]}"
        raise ValueError(msg) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise TimeoutError("timeout") from exc
        raise

    data = json.loads(raw)
    tweets = data.get("data", [])
    includes = data.get("includes", {})
    users = includes.get("users", []) if isinstance(includes, dict) else []
    user_by_id = {}
    for u in users:
        if isinstance(u, dict) and u.get("id"):
            user_by_id[str(u["id"])] = u

    reports = []
    now_stamp = int(time.time())
    for idx, tw in enumerate(tweets):
        if not isinstance(tw, dict):
            continue
        text = str(tw.get("text", "")).strip()
        tweet_id = str(tw.get("id", "")).strip()
        if not text or not tweet_id:
            continue
        author_id = str(tw.get("author_id", "")).strip()
        user = user_by_id.get(author_id, {})
        username = str(user.get("username", "")).strip() or "unknown"
        created_at = str(tw.get("created_at", "")).strip() or datetime.now(timezone.utc).isoformat()
        lang = str(tw.get("lang", "")).strip() or "und"

        incident_type = detect_incident_type(text)
        title = text if len(text) <= 140 else text[:137] + "..."
        preview = text if len(text) <= 220 else text[:217] + "..."

        reports.append(
            {
                "id": f"x-{tweet_id}",
                "source": f"@{username}",
                "platform": "X",
                "language": lang,
                "region": "Unknown",
                "city": "Unknown",
                "actor": "Unknown",
                "target": "Unknown",
                "incidentType": incident_type,
                "reportedAt": created_at,
                "title": title,
                "url": f"https://x.com/{username}/status/{tweet_id}",
                "preview": preview,
                "summary": "Imported from X recent search. Context and claims require independent verification.",
                "aiImageRisk": "Unclear",
                "importedAt": now_stamp + idx,
            }
        )

    return reports


def _safe_parse_iso_date(value: str) -> str:
    s = str(value or "").strip()
    if not s:
        return datetime.now(timezone.utc).isoformat()
    try:
        # GDELT often uses 20260304T123000Z
        if re.match(r"^\d{8}T\d{6}Z$", s):
            dt = datetime.strptime(s, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            return dt.isoformat()
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _strip_html_text(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", str(value or ""))
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _http_get_text(url: str, timeout: float = 10.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "codex-conflict-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _build_report(
    report_id: str,
    source: str,
    platform: str,
    language: str,
    reported_at: str,
    title: str,
    url: str,
    preview: str,
    summary: str,
) -> dict:
    incident_type = detect_incident_type(f"{title} {preview}")
    actor, region, city = infer_actor_region_city(f"{title} {preview} {summary}")
    return {
        "id": report_id,
        "source": source,
        "platform": platform,
        "language": language or "und",
        "region": region,
        "city": city,
        "actor": actor,
        "target": "Unknown",
        "incidentType": incident_type,
        "reportedAt": _safe_parse_iso_date(reported_at),
        "title": title[:200],
        "url": url,
        "preview": preview[:260],
        "summary": summary[:320],
        "aiImageRisk": "Unclear",
        "importedAt": int(time.time()),
    }


def fetch_gdelt_reports(query: str, limit: int) -> list:
    params = urllib.parse.urlencode(
        {
            "query": query,
            "mode": "ArtList",
            "maxrecords": str(limit),
            "format": "json",
            "sort": "datedesc",
        }
    )
    raw = _http_get_text(f"https://api.gdeltproject.org/api/v2/doc/doc?{params}", timeout=12.0)
    data = json.loads(raw)
    articles = data.get("articles", [])
    reports = []
    for a in articles:
        if not isinstance(a, dict):
            continue
        title = str(a.get("title", "")).strip()
        url = str(a.get("url", "")).strip()
        if not title or not url:
            continue
        domain = str(a.get("domain", "")).strip() or "GDELT source"
        seendate = str(a.get("seendate", "")).strip()
        lang = str(a.get("language", "")).strip() or "und"
        snippet = str(a.get("snippet", "")).strip() or title
        rid = "gdelt-" + hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
        reports.append(
            _build_report(
                report_id=rid,
                source=domain,
                platform="GDELT",
                language=lang,
                reported_at=seendate,
                title=title,
                url=url,
                preview=snippet,
                summary="Imported from GDELT open news index. Claims require independent verification.",
            )
        )
    return reports


def fetch_reliefweb_reports(query: str, limit: int) -> list:
    params = urllib.parse.urlencode(
        {
            "appname": "conflict-incident-monitor",
            "limit": str(limit),
            "profile": "full",
            "sort[]": "date:desc",
            "query[value]": query,
            "query[fields][]": ["title", "body"],
        },
        doseq=True,
    )
    raw = _http_get_text(f"https://api.reliefweb.int/v1/reports?{params}", timeout=12.0)
    data = json.loads(raw)
    items = data.get("data", [])
    reports = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rid_raw = str(item.get("id", "")).strip()
        fields = item.get("fields", {}) if isinstance(item.get("fields"), dict) else {}
        title = str(fields.get("title", "")).strip()
        if not title:
            continue
        date_obj = fields.get("date", {}) if isinstance(fields.get("date"), dict) else {}
        created = str(date_obj.get("created", "")).strip()
        body = _strip_html_text(fields.get("body-html") or fields.get("body") or "")
        preview = body[:220] if body else title
        source_name = "ReliefWeb"
        srcs = fields.get("source", [])
        if isinstance(srcs, list) and srcs and isinstance(srcs[0], dict):
            source_name = str(srcs[0].get("name", "")).strip() or source_name
        link = str(fields.get("url", "")).strip()
        if not link:
            alias = str(fields.get("url_alias", "")).strip()
            if alias:
                link = f"https://reliefweb.int{alias if alias.startswith('/') else '/' + alias}"
        if not link:
            link = "https://reliefweb.int/"
        rid = "rw-" + (rid_raw if rid_raw else hashlib.sha1(link.encode("utf-8")).hexdigest()[:16])
        reports.append(
            _build_report(
                report_id=rid,
                source=source_name,
                platform="ReliefWeb",
                language="en",
                reported_at=created,
                title=title,
                url=link,
                preview=preview,
                summary="Imported from ReliefWeb humanitarian reports feed.",
            )
        )
    return reports


def fetch_telegram_reports(channels: list, limit: int, query: str = "") -> list:
    if not channels:
        return []
    per_channel = max(3, min(25, (limit // max(1, len(channels))) + 2))
    query_l = (query or "").strip().lower()
    reports = []
    for ch in channels:
        if not ch:
            continue
        url = f"https://t.me/s/{urllib.parse.quote(ch)}"
        try:
            raw = _http_get_text(url, timeout=10.0)
        except Exception:
            continue

        # Parse each post block by data-post marker.
        for m in re.finditer(r'data-post="([^"]+)".*?class="tgme_widget_message_text[^"]*">(.*?)</div>', raw, re.S):
            post_ref = m.group(1)
            post_html = m.group(2)
            text = _strip_html_text(post_html)
            if not text:
                continue
            if query_l and query_l not in text.lower():
                # keep if looks like conflict action even if query misses
                if detect_incident_type(text) == "conflict report":
                    continue
            post_link = f"https://t.me/{post_ref}"
            time_match = re.search(rf'data-post="{re.escape(post_ref)}".*?<time[^>]*datetime="([^"]+)"', raw, re.S)
            dt = time_match.group(1) if time_match else ""
            rid = "tg-" + hashlib.sha1(post_link.encode("utf-8")).hexdigest()[:16]
            reports.append(
                _build_report(
                    report_id=rid,
                    source=f"@{ch}",
                    platform="Telegram",
                    language="und",
                    reported_at=dt,
                    title=text[:140] + ("..." if len(text) > 140 else ""),
                    url=post_link,
                    preview=text[:230],
                    summary="Imported from public Telegram channel page scrape.",
                )
            )
            if len([r for r in reports if r.get("source") == f"@{ch}"]) >= per_channel:
                break

    reports.sort(key=lambda r: str(r.get("reportedAt", "")), reverse=True)
    return reports[:limit]


def fetch_free_sources_reports(query: str, channels: list, limit: int) -> list:
    part = max(5, min(60, limit // 3))
    all_reports = []
    try:
        all_reports.extend(fetch_gdelt_reports(query, part))
    except Exception:
        pass
    try:
        all_reports.extend(fetch_reliefweb_reports(query, part))
    except Exception:
        pass
    try:
        all_reports.extend(fetch_telegram_reports(channels, part, query=query))
    except Exception:
        pass

    dedup = {}
    for r in all_reports:
        if not isinstance(r, dict):
            continue
        key = str(r.get("url", "")).strip() or str(r.get("id", "")).strip()
        if not key:
            continue
        dedup[key] = r
    merged = list(dedup.values())
    merged.sort(key=lambda r: str(r.get("reportedAt", "")), reverse=True)
    return merged[:limit]


def main():
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"Serving on http://{host}:{port}")
    print("Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH (PBKDF2) for production.")
    print("Compatibility fallback: ADMIN_PASSWORD is accepted only when hash is not configured.")
    print(f"State file: {STATE_FILE}")
    server.serve_forever()


if __name__ == "__main__":
    main()
