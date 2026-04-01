from __future__ import annotations

import hashlib
import hmac
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, Response, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import load_firebase_settings, load_server_settings
from firebase_store import FirebaseScriptStore
from loader_builder import shared_key_reader_lua


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # type: ignore[assignment]

firebase_settings = load_firebase_settings()
server_settings = load_server_settings()
store = FirebaseScriptStore(firebase_settings)

request_buckets: dict[str, deque[float]] = defaultdict(deque)

RATE_LIMITS = {
    "upload": (45, server_settings.rate_limit_window_seconds),
    "loader": (240, server_settings.rate_limit_window_seconds),
    "signed": (180, server_settings.rate_limit_window_seconds),
    "raw": (180, server_settings.rate_limit_window_seconds),
}


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


def rate_limited(bucket_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not apply_rate_limit(bucket_name):
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


def no_store_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
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

    loader_source = (
        shared_key_reader_lua()
        + f"""
local key = readScriptKey()
if type(key) ~= "string" or key == "" then
    error("Missing script_key")
end

local HttpService = game:GetService("HttpService")
local signedUrl = "{server_settings.public_base_url}/signed/{script_id}?key=" .. HttpService:UrlEncode(key)
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
        return Response("Missing script key", status=403)

    expected_hash = store.hash_key(provided_key, record.key_salt)
    if not hmac.compare_digest(expected_hash, record.key_hash):
        return Response("Invalid script key", status=403)

    ts = str(int(time.time()))
    sig = sign_raw_request(script_id, ts)
    raw_url = (
        f"{server_settings.public_base_url}/raw/{script_id}"
        f"?token={record.token}&ts={ts}&sig={sig}"
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
        return Response("Missing fields", status=403)

    if not hmac.compare_digest(token, record.token):
        return Response("Invalid token", status=403)

    try:
        ts_int = int(ts)
    except ValueError:
        return Response("Bad timestamp", status=403)

    if abs(time.time() - ts_int) > server_settings.signed_url_ttl_seconds:
        return Response("Expired request", status=403)

    expected = sign_raw_request(script_id, ts)
    if not hmac.compare_digest(expected, sig):
        return Response("Invalid signature", status=403)

    if not roblox_only(request):
        return Response("Access denied", status=403)

    return Response(record.raw_script, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=server_settings.port, debug=False)
