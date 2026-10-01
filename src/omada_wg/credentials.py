from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import os
from pathlib import Path

from .errors import AuthenticationError
from .secretstore import DpapiSessionStore


@dataclass(frozen=True)
class CloudCredentials:
    username: str
    password: str


class CredentialStore:
    def __init__(self, path: str | Path):
        self._store = DpapiSessionStore(path)

    def save(self, credentials: CloudCredentials) -> None:
        if not credentials.username or not credentials.password:
            raise AuthenticationError("Cloud username and password are required")
        self._store.save({"username": credentials.username, "password": credentials.password})

    def load(self) -> CloudCredentials:
        value = self._store.load()
        try:
            username, password = value["username"], value["password"]
        except KeyError as exc:
            raise AuthenticationError("Encrypted credential file is missing required fields") from exc
        if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
            raise AuthenticationError("Encrypted credential file contains invalid credentials")
        return CloudCredentials(username, password)


class PortableCredentialStore:
    """AES-GCM deployment vault that can be copied to another Windows machine."""

    magic = b"OMADAWG1\0"

    def __init__(self, path: str | Path, key: bytes):
        if len(key) != 32:
            raise AuthenticationError("Deployment credential key must be 32 bytes")
        self.path = Path(path)
        self.key = key

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def encode_key(key: bytes) -> str:
        return base64.urlsafe_b64encode(key).decode("ascii")

    @staticmethod
    def decode_key(value: str) -> bytes:
        try:
            key = base64.urlsafe_b64decode(value.encode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise AuthenticationError("Deployment credential key is invalid") from exc
        if len(key) != 32:
            raise AuthenticationError("Deployment credential key is invalid")
        return key

    def save(self, credentials: CloudCredentials) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not credentials.username or not credentials.password:
            raise AuthenticationError("Cloud username and password are required")
        nonce = os.urandom(12)
        plain = json.dumps({"username": credentials.username, "password": credentials.password},
                           separators=(",", ":")).encode("utf-8")
        protected = AESGCM(self.key).encrypt(nonce, plain, self.magic)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_bytes(self.magic + nonce + protected)
        os.chmod(temp, 0o600)
        temp.replace(self.path)

    def load(self) -> CloudCredentials:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            value = self.path.read_bytes()
            if not value.startswith(self.magic) or len(value) < len(self.magic) + 28:
                raise AuthenticationError("Encrypted deployment credential file is invalid")
            rest = value[len(self.magic):]
            plain = AESGCM(self.key).decrypt(rest[:12], rest[12:], self.magic)
            data = json.loads(plain.decode("utf-8"))
            return CloudCredentials(data["username"], data["password"])
        except AuthenticationError:
            raise
        except (OSError, InvalidTag, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise AuthenticationError("Cannot decrypt deployment credentials") from exc
