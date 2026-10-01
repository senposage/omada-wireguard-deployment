from __future__ import annotations

import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .errors import AuthenticationError


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[_Blob, Any]:
    buffer = ctypes.create_string_buffer(data)
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _crypt(data: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise AuthenticationError("The browser session store currently requires Windows DPAPI")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, keepalive = _blob(data)
    out_blob = _Blob()
    if decrypt:
        ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    else:
        ok = crypt32.CryptProtectData(ctypes.byref(in_blob), "Omada WireGuard session", None, None, None, 0,
                                      ctypes.byref(out_blob))
    del keepalive
    if not ok:
        raise AuthenticationError("Windows could not protect the Omada session")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


class DpapiSessionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def save(self, value: dict[str, Any]) -> None:
        encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        protected = _crypt(encoded, decrypt=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_bytes(protected)
        os.chmod(temp, 0o600)
        temp.replace(self.path)

    def load(self) -> dict[str, Any]:
        try:
            protected = self.path.read_bytes()
            return json.loads(_crypt(protected, decrypt=True).decode("utf-8"))
        except OSError as exc:
            raise AuthenticationError(f"Cannot read encrypted Omada session: {exc}") from exc
        except (ValueError, json.JSONDecodeError) as exc:
            raise AuthenticationError("The encrypted Omada session is invalid") from exc

