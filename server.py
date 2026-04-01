from __future__ import annotations

import base64
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


def stream_seed(material: str) -> int:
    seed = 2166136261
    for index, char in enumerate(material.encode("utf-8"), start=1):
        seed = (seed ^ (char + index)) & 0xFFFFFFFF
        seed = (seed * 16777619) & 0xFFFFFFFF
    return seed or 1


def xor_stream_crypt(data: bytes, material: str) -> bytes:
    state = stream_seed(material)
    output = bytearray()
    length = len(data)

    for index, value in enumerate(data):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= (state >> 17) & 0xFFFFFFFF
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        mask = (state & 0xFF) ^ ((index * 31 + length) & 0xFF)
        output.append(value ^ mask)

    return bytes(output)


def roblox_only(req) -> bool:
    ua = (req.headers.get("User-Agent") or "").lower()

    blocked = [
        "mozilla",
        "chrome",
        "safari",
        "edge",
        "opera",
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
        "postman",
        "insomnia",
    ]

    if any(token in ua for token in blocked):
        return False

    if ua.startswith("roblox"):
        return True

    # Some executors do not send a clean Roblox UA.
    # If it is not obviously a browser/tool, allow it.
    return ua != ""


def no_store_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def build_encrypted_runtime(script_source: str, script_id: str, provided_key: str) -> str:
    nonce = secrets.token_urlsafe(8)
    material = f"{provided_key}:{script_id}:{nonce}"
    payload = base64.b64encode(xor_stream_crypt(script_source.encode("utf-8"), material)).decode("ascii")

    return f"""
local function readScriptKey()
    if type(script_key) == "string" and script_key ~= "" then
        return script_key
    end

    local env = getgenv and getgenv() or nil
    if env and type(env.script_key) == "string" and env.script_key ~= "" then
        return env.script_key
    end

    if _G and type(_G.script_key) == "string" and _G.script_key ~= "" then
        return _G.script_key
    end

    if shared and type(shared.script_key) == "string" and shared.script_key ~= "" then
        return shared.script_key
    end

    return nil
end

local alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local function base64Decode(data)
    data = string.gsub(data, '[^' .. alphabet .. '=]', '')
    return (data:gsub('.', function(char)
        if char == '=' then
            return ''
        end

        local value = string.find(alphabet, char, 1, true) - 1
        local bits = ''
        for bit = 6, 1, -1 do
            bits = bits .. ((value % 2 ^ bit - value % 2 ^ (bit - 1) > 0) and '1' or '0')
        end
        return bits
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(byte)
        if #byte ~= 8 then
            return ''
        end

        local value = 0
        for i = 1, 8 do
            if byte:sub(i, i) == '1' then
                value = value + 2 ^ (8 - i)
            end
        end
        return string.char(value)
    end))
end

local function seedFromText(text)
    local seed = 2166136261
    for i = 1, #text do
        seed = bit32.band(bit32.bxor(seed, string.byte(text, i) + i), 0xFFFFFFFF)
        seed = bit32.band(seed * 16777619, 0xFFFFFFFF)
    end
    if seed == 0 then
        seed = 1
    end
    return seed
end

local function nextMask(state, index, length)
    state = bit32.band(bit32.bxor(state, bit32.lshift(state, 13)), 0xFFFFFFFF)
    state = bit32.band(bit32.bxor(state, bit32.rshift(state, 17)), 0xFFFFFFFF)
    state = bit32.band(bit32.bxor(state, bit32.lshift(state, 5)), 0xFFFFFFFF)
    local mask = bit32.bxor(bit32.band(state, 0xFF), bit32.band(((index - 1) * 31 + length), 0xFF))
    return state, mask
end

local function decryptPayload(payload, material)
    local decoded = base64Decode(payload)
    local length = #decoded
    local state = seedFromText(material)
    local parts = {{}}
    local chunkIndex = 1

    for i = 1, length do
        local mask
        state, mask = nextMask(state, i, length)
        parts[chunkIndex][#parts[chunkIndex] + 1] = string.char(bit32.bxor(string.byte(decoded, i), mask))
        if #parts[chunkIndex] >= 2048 then
            chunkIndex = chunkIndex + 1
            parts[chunkIndex] = {{}}
        end
    end

    for i = 1, #parts do
        parts[i] = table.concat(parts[i])
    end

    return table.concat(parts)
end

local key = readScriptKey()
if type(key) ~= 'string' or key == '' then
    error('Missing script_key')
end

local source = decryptPayload('{payload}', key .. ':{script_id}:{nonce}')
loadstring(source)()
""".strip()


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

    return jsonify(
        {
            "script_id": bundle.script_id,
            "loader": bundle.final_snippet,
        }
    )


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

    if not roblox_only(request):
        return Response("Access denied", status=403)

    provided_key = request.args.get("key", "")
    if not provided_key:
        return Response("Missing script key", status=403)

    expected_hash = store.hash_key(provided_key, record.key_salt)
    if not hmac.compare_digest(expected_hash, record.key_hash):
        return Response("Invalid script key", status=403)

    runtime = build_encrypted_runtime(record.raw_script, script_id, provided_key)
    return Response(runtime, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=server_settings.port, debug=False)
