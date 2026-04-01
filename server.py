from __future__ import annotations

import json
import hashlib
import hmac
import secrets
import threading
import time
from urllib import request as urllib_request
from collections import defaultdict, deque
from functools import wraps
from threading import Lock

from flask import Flask, Response, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import load_firebase_settings, load_server_settings
from firebase_store import FirebaseScriptStore
from loader_builder import shared_key_reader_lua


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # type: ignore[assignment]

firebase_settings = load_firebase_settings()
server_settings = load_server_settings()
store = FirebaseScriptStore(firebase_settings, server_settings.secret)

request_buckets: dict[str, deque[float]] = defaultdict(deque)
security_buckets: dict[str, deque[float]] = defaultdict(deque)
blocked_clients: dict[str, float] = {}
used_loader_tickets: dict[str, float] = {}
used_raw_signatures: dict[str, float] = {}
state_lock = Lock()

RATE_LIMITS = {
    "upload": (45, server_settings.rate_limit_window_seconds),
    "loader": (240, server_settings.rate_limit_window_seconds),
    "signed": (180, server_settings.rate_limit_window_seconds),
    "raw": (180, server_settings.rate_limit_window_seconds),
}
SUSPICIOUS_ATTEMPT_LIMIT = 6
SUSPICIOUS_WINDOW_SECONDS = 180
BLOCK_DURATION_SECONDS = 900


def server_secret_bytes() -> bytes:
    return server_settings.secret.encode("utf-8")


def get_client_ip() -> str:
    forwarded = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def apply_rate_limit(bucket_name: str) -> bool:
    max_requests, window_seconds = RATE_LIMITS[bucket_name]
    now = time.time()
    key = f"{bucket_name}:{get_client_ip()}"
    bucket = request_buckets[key]

    while bucket and now - bucket[0] > window_seconds:
        bucket.popleft()

    if len(bucket) >= max_requests:
        return False

    bucket.append(now)
    return True


def cleanup_expired_entries(store_map: dict[str, float], now: float) -> None:
    expired_keys = [key for key, expires_at in store_map.items() if expires_at <= now]
    for key in expired_keys:
        store_map.pop(key, None)


def is_temporarily_blocked() -> bool:
    now = time.time()
    client_ip = get_client_ip()
    with state_lock:
        cleanup_expired_entries(blocked_clients, now)
        expires_at = blocked_clients.get(client_ip)
        return bool(expires_at and expires_at > now)


def mark_suspicious_attempt() -> int:
    now = time.time()
    client_ip = get_client_ip()
    with state_lock:
        cleanup_expired_entries(blocked_clients, now)
        bucket = security_buckets[client_ip]
        while bucket and now - bucket[0] > SUSPICIOUS_WINDOW_SECONDS:
            bucket.popleft()
        bucket.append(now)
        if len(bucket) >= SUSPICIOUS_ATTEMPT_LIMIT:
            blocked_clients[client_ip] = now + BLOCK_DURATION_SECONDS
        return len(bucket)


def consume_once(store_map: dict[str, float], key: str, ttl_seconds: int) -> bool:
    now = time.time()
    with state_lock:
        cleanup_expired_entries(store_map, now)
        if key in store_map:
            return False
        store_map[key] = now + ttl_seconds
        return True


def rate_limited(bucket_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if is_temporarily_blocked():
                send_security_alert("blocked_ip", kwargs.get("script_id"), {"bucket": bucket_name})
                return Response("Temporarily blocked", status=403)
            if not apply_rate_limit(bucket_name):
                send_security_alert("rate_limit_exceeded", kwargs.get("script_id"), {"bucket": bucket_name})
                return jsonify({"error": "Rate limit exceeded"}), 429
            return func(*args, **kwargs)

        return wrapper

    return decorator


def require_upload_api_key() -> Response | None:
    provided = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided, server_settings.upload_api_key):
        return jsonify({"error": "Unauthorized"}), 401
    return None


def roblox_only(req) -> bool:
    ua = (req.headers.get("User-Agent") or "").lower()
    blocked = [
        "curl",
        "wget",
        "python",
        "requests",
        "powershell",
        "fetch",
        "httpclient",
        "java",
        "node",
        "httpx",
        "aiohttp",
    ]

    if any(item in ua for item in blocked):
        return False

    return ua.startswith("roblox")


def sign_raw_request(script_id: str, ts: str) -> str:
    message = f"{script_id}{ts}".encode("utf-8")
    return hmac.new(server_secret_bytes(), message, hashlib.sha256).hexdigest()


def sign_loader_ticket(script_id: str, ts: str, nonce: str, client_ip: str) -> str:
    message = f"{script_id}:{ts}:{nonce}:{client_ip}".encode("utf-8")
    return hmac.new(server_secret_bytes(), message, hashlib.sha256).hexdigest()


def post_webhook(payload: dict[str, object]) -> None:
    if not server_settings.alert_webhook_url:
        return

    body = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        server_settings.alert_webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass


def send_security_alert(reason: str, script_id: str | None, extra: dict[str, object] | None = None) -> None:
    if not server_settings.alert_webhook_url:
        return

    client_ip = get_client_ip()
    payload = {
        "embeds": [
            {
                "title": "Source access alert",
                "color": 0xFFFFFF,
                "fields": [
                    {"name": "Reason", "value": reason, "inline": True},
                    {"name": "Script ID", "value": script_id or "unknown", "inline": True},
                    {"name": "IP", "value": client_ip, "inline": True},
                    {"name": "Method", "value": request.method, "inline": True},
                    {"name": "Path", "value": request.path, "inline": True},
                    {"name": "User-Agent", "value": (request.headers.get("User-Agent") or "unknown")[:1024], "inline": False},
                ],
            }
        ]
    }

    if extra:
        compact = json.dumps(extra, ensure_ascii=True)[:1000]
        payload["embeds"][0]["fields"].append({"name": "Details", "value": compact or "{}", "inline": False})

    threading.Thread(target=post_webhook, args=(payload,), daemon=True).start()


def deny_access(message: str, status_code: int, reason: str, script_id: str | None, extra: dict[str, object] | None = None) -> Response:
    attempts = mark_suspicious_attempt()
    details = dict(extra or {})
    details["attempts"] = attempts
    details["blocked"] = is_temporarily_blocked()
    send_security_alert(reason, script_id, details)
    return Response(message, status=status_code)


def build_watermarked_script(script_id: str, script_source: str) -> str:
    client_ip = get_client_ip()
    stamp = str(int(time.time()))
    marker = hmac.new(
        server_secret_bytes(),
        f"{script_id}:{client_ip}:{stamp}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"-- luadec delivery marker: {script_id}:{stamp}:{marker}\n{script_source}"


def no_store_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.after_request
def add_security_headers(response: Response) -> Response:
    return no_store_headers(response)


@app.get("/health")
def health() -> Response:
    return jsonify({"ok": True})


@app.post("/api/upload")
@rate_limited("upload")
def upload_script() -> Response:
    unauthorized = require_upload_api_key()
    if unauthorized:
        return unauthorized

    data = request.get_json(silent=True) or {}
    script = data.get("script", "")
    script_key = data.get("script_key", "")
    script_name = data.get("script_name", "script.lua")
    owner_id = data.get("owner_id", "discord")
    owner_name = data.get("owner_name", "discord")

    if not script.strip():
        return jsonify({"error": "Missing script"}), 400

    if not script_key.strip():
        return jsonify({"error": "Missing script_key"}), 400

    if not (6 <= len(script_key) <= 128):
        return jsonify({"error": "script_key must be between 6 and 128 characters"}), 400

    bundle = store.create_script(
        script_name=script_name,
        script_source=script,
        script_key=script_key.strip(),
        owner_id=owner_id,
        owner_name=owner_name,
        public_base_url=server_settings.public_base_url,
    )

    return jsonify({"script_id": bundle.script_id, "loader": bundle.final_snippet})


@app.get("/loader/<script_id>")
@rate_limited("loader")
def loader(script_id: str) -> Response:
    record = store.get_script(script_id)
    if not record:
        return Response("Not found", status=404)

    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(8)
    ticket = sign_loader_ticket(script_id, ts, nonce, get_client_ip())
    loader_source = (
        shared_key_reader_lua()
        + f"""
local key = readScriptKey()
if type(key) ~= "string" or key == "" then
    error("Missing script_key")
end

local HttpService = game:GetService("HttpService")
local signedUrl = "{server_settings.public_base_url}/signed/{script_id}?ts={ts}&nonce={nonce}&ticket={ticket}&key=" .. HttpService:UrlEncode(key)
loadstring(game:HttpGet(signedUrl))()
"""
    )
    return Response(loader_source, mimetype="text/plain")


@app.get("/signed/<script_id>")
@rate_limited("signed")
def signed(script_id: str) -> Response:
    record = store.get_script(script_id)
    if not record:
        return Response("Not found", status=404)

    provided_key = request.args.get("key", "")
    if not provided_key:
        return deny_access("Missing script key", 403, "missing_script_key", script_id)

    ts = request.args.get("ts", "")
    nonce = request.args.get("nonce", "")
    ticket = request.args.get("ticket", "")
    if not ts or not nonce or not ticket:
        return deny_access(
            "Access denied",
            403,
            "missing_loader_ticket",
            script_id,
            {"has_ts": bool(ts), "has_nonce": bool(nonce), "has_ticket": bool(ticket)},
        )

    try:
        ts_int = int(ts)
    except ValueError:
        return deny_access("Access denied", 403, "bad_loader_timestamp", script_id)

    if abs(time.time() - ts_int) > server_settings.signed_url_ttl_seconds:
        return deny_access("Access denied", 403, "expired_loader_ticket", script_id)

    expected_ticket = sign_loader_ticket(script_id, ts, nonce, get_client_ip())
    if not hmac.compare_digest(expected_ticket, ticket):
        return deny_access("Access denied", 403, "invalid_loader_ticket", script_id)

    if not consume_once(used_loader_tickets, f"{script_id}:{ticket}", server_settings.signed_url_ttl_seconds):
        return deny_access("Access denied", 403, "replayed_loader_ticket", script_id)

    expected_hash = store.hash_key(provided_key, record.key_salt)
    if not hmac.compare_digest(expected_hash, record.key_hash):
        return deny_access("Invalid script key", 403, "invalid_script_key", script_id)

    raw_ts = str(int(time.time()))
    sig = sign_raw_request(script_id, raw_ts)
    raw_url = (
        f"{server_settings.public_base_url}/raw/{script_id}"
        f"?token={record.token}&ts={raw_ts}&sig={sig}"
    )

    return Response(f'loadstring(game:HttpGet("{raw_url}"))()', mimetype="text/plain")


@app.get("/raw/<script_id>")
@rate_limited("raw")
def raw(script_id: str) -> Response:
    record = store.get_script(script_id)
    if not record:
        return Response("Not found", status=404)

    token = request.args.get("token", "")
    ts = request.args.get("ts", "")
    sig = request.args.get("sig", "")

    if not token or not ts or not sig:
        return deny_access("Missing fields", 403, "missing_raw_fields", script_id)

    if not hmac.compare_digest(token, record.token):
        return deny_access("Invalid token", 403, "invalid_raw_token", script_id)

    try:
        ts_int = int(ts)
    except ValueError:
        return deny_access("Bad timestamp", 403, "bad_raw_timestamp", script_id)

    if abs(time.time() - ts_int) > server_settings.signed_url_ttl_seconds:
        return deny_access("Expired request", 403, "expired_raw_request", script_id)

    expected = sign_raw_request(script_id, ts)
    if not hmac.compare_digest(expected, sig):
        return deny_access("Invalid signature", 403, "invalid_raw_signature", script_id)

    if not consume_once(used_raw_signatures, f"{script_id}:{sig}", server_settings.signed_url_ttl_seconds):
        return deny_access("Access denied", 403, "replayed_raw_signature", script_id)

    if not roblox_only(request):
        return deny_access(
            "Access denied",
            403,
            "blocked_non_roblox_fetch",
            script_id,
            {"referer": request.headers.get("Referer", "")[:300]},
        )

    return Response(build_watermarked_script(script_id, record.raw_script), mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=server_settings.port, debug=False)
