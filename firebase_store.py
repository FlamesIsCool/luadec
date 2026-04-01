from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

import firebase_admin
from firebase_admin import credentials, firestore
from cryptography.fernet import Fernet, InvalidToken

from config import FirebaseSettings
from loader_builder import build_final_snippet


@dataclass(slots=True)
class ScriptRecord:
    script_id: str
    script_name: str
    raw_script: str
    token: str
    key_hash: str
    key_salt: str
    created_at: int


@dataclass(slots=True)
class UploadBundle:
    script_id: str
    final_snippet: str


class FirebaseScriptStore:
    def __init__(self, settings: FirebaseSettings, encryption_secret: str) -> None:
        self._settings = settings
        self._app = self._init_app(settings)
        self._db = firestore.client(app=self._app)
        self._cipher = Fernet(self._derive_cipher_key(encryption_secret))

    @staticmethod
    def _init_app(settings: FirebaseSettings) -> firebase_admin.App:
        try:
            return firebase_admin.get_app()
        except ValueError:
            pass

        if settings.service_account_info:
            cred = credentials.Certificate(settings.service_account_info)
        elif settings.service_account_path:
            cred = credentials.Certificate(str(settings.service_account_path))
        else:
            raise RuntimeError("Missing Firebase credentials.")

        return firebase_admin.initialize_app(cred, {"projectId": settings.project_id})

    @staticmethod
    def hash_key(script_key: str, salt: str) -> str:
        digest = hashlib.scrypt(
            script_key.encode("utf-8"),
            salt=base64.urlsafe_b64decode(salt.encode("ascii")),
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )
        return base64.urlsafe_b64encode(digest).decode("ascii")

    @staticmethod
    def create_key_hash(script_key: str) -> tuple[str, str]:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
        return FirebaseScriptStore.hash_key(script_key, salt), salt

    @staticmethod
    def _derive_cipher_key(secret: str) -> bytes:
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    def encrypt_script(self, script_source: str) -> str:
        encrypted = self._cipher.encrypt(script_source.encode("utf-8"))
        return encrypted.decode("ascii")

    def decrypt_script(self, encrypted_script: str) -> str:
        try:
            plaintext = self._cipher.decrypt(encrypted_script.encode("ascii"))
        except InvalidToken as exc:
            raise RuntimeError("Stored script could not be decrypted.") from exc
        return plaintext.decode("utf-8")

    def create_script(
        self,
        *,
        script_name: str,
        script_source: str,
        script_key: str,
        owner_id: int | str,
        owner_name: str,
        public_base_url: str,
    ) -> UploadBundle:
        script_id = secrets.token_hex(4)
        token = secrets.token_urlsafe(12)
        created_at = int(time.time())
        key_hash, key_salt = self.create_key_hash(script_key)

        self._db.collection(self._settings.collection).document(script_id).set(
            {
                "script_id": script_id,
                "script_name": script_name,
                "script_size": len(script_source.encode("utf-8")),
                "owner_id": str(owner_id),
                "owner_name": owner_name,
                "created_at": created_at,
                "encrypted_script": self.encrypt_script(script_source),
                "token": token,
                "key_hash": key_hash,
                "key_salt": key_salt,
            }
        )

        primary_loader_url = f"{public_base_url.rstrip('/')}/loader/{script_id}"
        final_snippet = build_final_snippet(
            script_key,
            primary_loader_url,
            self._settings.project_id,
            self._settings.collection,
            script_id,
        )
        return UploadBundle(script_id=script_id, final_snippet=final_snippet)

    def get_script(self, script_id: str) -> ScriptRecord | None:
        document = self._db.collection(self._settings.collection).document(script_id)
        snapshot = document.get()
        if not snapshot.exists:
            return None

        data: dict[str, Any] = snapshot.to_dict() or {}
        token = str(data.get("token", ""))
        if not token:
            token = secrets.token_urlsafe(12)
            document.update({"token": token})

        encrypted_script = str(data.get("encrypted_script", ""))
        raw_script = str(data.get("raw_script", ""))
        if encrypted_script:
            resolved_script = self.decrypt_script(encrypted_script)
        elif raw_script:
            resolved_script = raw_script
            document.update(
                {
                    "encrypted_script": self.encrypt_script(raw_script),
                    "raw_script": firestore.DELETE_FIELD,
                }
            )
        else:
            resolved_script = ""

        return ScriptRecord(
            script_id=script_id,
            script_name=str(data.get("script_name", "")),
            raw_script=resolved_script,
            token=token,
            key_hash=str(data.get("key_hash", "")),
            key_salt=str(data.get("key_salt", "")),
            created_at=int(data.get("created_at", 0) or 0),
        )
