from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


load_dotenv()


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


@dataclass(slots=True)
class FirebaseSettings:
    project_id: str
    collection: str
    service_account_path: Path | None
    service_account_info: dict[str, Any] | None


@dataclass(slots=True)
class BotSettings:
    discord_token: str
    server_base_url: str
    server_upload_api_key: str


@dataclass(slots=True)
class ServerSettings:
    public_base_url: str
    upload_api_key: str
    secret: str
    alert_webhook_url: str | None
    port: int
    signed_url_ttl_seconds: int
    rate_limit_window_seconds: int


def load_firebase_settings() -> FirebaseSettings:
    service_account_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    service_account_path_raw = os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH", "").strip()

    service_account_info = json.loads(service_account_json) if service_account_json else None
    service_account_path = Path(service_account_path_raw) if service_account_path_raw else None

    if not service_account_info and not service_account_path:
        raise RuntimeError(
            "Set FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_PATH before starting the app."
        )

    return FirebaseSettings(
        project_id=require_env("FIREBASE_PROJECT_ID"),
        collection=os.environ.get("FIREBASE_COLLECTION", "scripts").strip() or "scripts",
        service_account_path=service_account_path,
        service_account_info=service_account_info,
    )


def load_bot_settings() -> BotSettings:
    return BotSettings(
        discord_token=require_env("DISCORD_TOKEN"),
        server_base_url=require_env("SERVER_BASE_URL").rstrip("/"),
        server_upload_api_key=require_env("SERVER_UPLOAD_API_KEY"),
    )


def load_server_settings() -> ServerSettings:
    return ServerSettings(
        public_base_url=require_env("PUBLIC_BASE_URL").rstrip("/"),
        upload_api_key=require_env("SERVER_UPLOAD_API_KEY"),
        secret=require_env("SERVER_SECRET"),
        alert_webhook_url=os.environ.get("DISCORD_ALERT_WEBHOOK_URL", "").strip() or None,
        port=int(os.environ.get("PORT", "5000")),
        signed_url_ttl_seconds=int(os.environ.get("SIGNED_URL_TTL_SECONDS", "15")),
        rate_limit_window_seconds=int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60")),
    )
