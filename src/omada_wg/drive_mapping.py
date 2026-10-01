from __future__ import annotations

import ctypes
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import BackendError, ConfigurationError


NO_ERROR = 0
ERROR_MORE_DATA = 234
ERROR_NOT_CONNECTED = 2250
RESOURCETYPE_DISK = 1
CONNECT_UPDATE_PROFILE = 1


@dataclass(frozen=True)
class DriveMapping:
    letter: str
    path: str


@dataclass(frozen=True)
class PreviousMapping:
    letter: str
    path: str | None
    persistent: bool
    username: str | None
    changed: bool


def normalize_drive_letter(value: str) -> str:
    letter = value.strip().upper().rstrip(":")
    if not re.fullmatch(r"[A-Z]", letter):
        raise ConfigurationError(f"Invalid drive letter: {value!r}")
    return letter + ":"


def parse_drive_maps(value: str | None) -> list[DriveMapping]:
    r"""Parse ``Z:=\\server\share; S:=\\server\scans`` admin input."""
    result: list[DriveMapping] = []
    seen: set[str] = set()
    for entry in re.split(r"[;\r\n]+", value or ""):
        entry = entry.strip()
        if not entry:
            continue
        match = re.fullmatch(r"\s*([A-Za-z]):?\s*=\s*(\\\\[^\\/]+\\.+?)\s*", entry)
        if not match:
            raise ConfigurationError(
                f"Invalid drive mapping {entry!r}; use Z:=\\\\nas.example.com\\Share")
        letter = normalize_drive_letter(match.group(1))
        path = match.group(2).rstrip("\\")
        if letter in seen:
            raise ConfigurationError(f"Drive {letter} is configured more than once")
        seen.add(letter)
        result.append(DriveMapping(letter, path))
    return result


class _NETRESOURCEW(ctypes.Structure):
    _fields_ = [
        ("dwScope", ctypes.c_ulong),
        ("dwType", ctypes.c_ulong),
        ("dwDisplayType", ctypes.c_ulong),
        ("dwUsage", ctypes.c_ulong),
        ("lpLocalName", ctypes.c_wchar_p),
        ("lpRemoteName", ctypes.c_wchar_p),
        ("lpComment", ctypes.c_wchar_p),
        ("lpProvider", ctypes.c_wchar_p),
    ]


class WindowsDriveProvider:
    def __init__(self) -> None:
        self.mpr = ctypes.windll.mpr

    @staticmethod
    def _message(code: int) -> str:
        try:
            return ctypes.FormatError(code).strip()
        except OSError:
            return f"Windows error {code}"

    def current(self, letter: str) -> str | None:
        size = ctypes.c_ulong(512)
        while True:
            buffer = ctypes.create_unicode_buffer(size.value)
            result = self.mpr.WNetGetConnectionW(letter, buffer, ctypes.byref(size))
            if result == NO_ERROR:
                return buffer.value
            if result == ERROR_NOT_CONNECTED:
                return None
            if result == ERROR_MORE_DATA:
                continue
            raise BackendError(f"Cannot read drive {letter}: {self._message(result)}")

    @staticmethod
    def saved_details(letter: str) -> tuple[bool, str | None, str | None]:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"Network\{letter[0]}") as key:
                try:
                    username, _ = winreg.QueryValueEx(key, "UserName")
                except FileNotFoundError:
                    username = None
                try:
                    remote_path, _ = winreg.QueryValueEx(key, "RemotePath")
                except FileNotFoundError:
                    remote_path = None
                return (True, str(username) if username else None,
                        str(remote_path) if remote_path else None)
        except FileNotFoundError:
            return False, None, None

    def remove(self, letter: str, *, persistent: bool) -> None:
        flags = CONNECT_UPDATE_PROFILE if persistent else 0
        result = self.mpr.WNetCancelConnection2W(letter, flags, True)
        if result not in (NO_ERROR, ERROR_NOT_CONNECTED):
            raise BackendError(f"Cannot unmap drive {letter}: {self._message(result)}")

    def add(self, mapping: DriveMapping, *, persistent: bool = False,
            username: str | None = None) -> None:
        resource = _NETRESOURCEW()
        resource.dwType = RESOURCETYPE_DISK
        resource.lpLocalName = mapping.letter
        resource.lpRemoteName = mapping.path
        flags = CONNECT_UPDATE_PROFILE if persistent else 0
        result = self.mpr.WNetAddConnection2W(
            ctypes.byref(resource), None, username, flags)
        if result != NO_ERROR:
            raise BackendError(
                f"Cannot map {mapping.letter} to {mapping.path}: {self._message(result)}")


class DriveMappingManager:
    def __init__(self, mappings: tuple[DriveMapping, ...] | list[DriveMapping],
                 state_path: Path, provider=None) -> None:
        self.mappings = tuple(mappings)
        self.state_path = state_path
        self.provider = provider or WindowsDriveProvider()

    def _load(self) -> list[PreviousMapping] | None:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise BackendError(f"Cannot read saved drive mappings: {exc}") from exc
        try:
            return [PreviousMapping(**item) for item in data["previous"]]
        except (KeyError, TypeError) as exc:
            raise BackendError("Saved drive mapping state is invalid") from exc

    def _save(self, previous: list[PreviousMapping]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(json.dumps({"previous": [asdict(item) for item in previous]}, indent=2),
                        encoding="utf-8")
        os.replace(temp, self.state_path)

    def connect(self) -> None:
        if not self.mappings:
            return
        previous = self._load()
        if previous is None:
            previous = []
            for mapping in self.mappings:
                current = self.provider.current(mapping.letter)
                persistent, username, saved_path = self.provider.saved_details(mapping.letter)
                previous.append(PreviousMapping(
                    mapping.letter, current or saved_path, persistent, username,
                    changed=current is None or current.casefold() != mapping.path.casefold()))
            # Save before changing anything so a crash can still be recovered.
            self._save(previous)
        try:
            by_letter = {item.letter: item for item in previous}
            for mapping in self.mappings:
                saved = by_letter.get(mapping.letter)
                if not saved or not saved.changed:
                    continue
                current = self.provider.current(mapping.letter)
                if current and current.casefold() == mapping.path.casefold():
                    continue
                if current or saved.persistent:
                    self.provider.remove(mapping.letter, persistent=saved.persistent)
                self.provider.add(mapping, persistent=False)
        except Exception:
            self.disconnect()
            raise

    def disconnect(self) -> None:
        previous = self._load()
        if previous is None:
            return
        errors: list[str] = []
        for saved in reversed(previous):
            if not saved.changed:
                continue
            try:
                current = self.provider.current(saved.letter)
                if current:
                    self.provider.remove(saved.letter, persistent=True)
                if saved.path:
                    self.provider.add(
                        DriveMapping(saved.letter, saved.path),
                        persistent=saved.persistent, username=saved.username)
            except Exception as exc:
                errors.append(str(exc))
        if not errors:
            try:
                self.state_path.unlink()
            except FileNotFoundError:
                pass
        if errors:
            raise BackendError("Could not restore drive mappings: " + "; ".join(errors))
