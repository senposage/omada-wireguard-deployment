from __future__ import annotations

import ctypes
import json
import os
import re
import time
from dataclasses import asdict, dataclass, replace
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
    restore_path: str | None = None


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


def _unc_path(value: str, *, label: str) -> str:
    path = value.strip().rstrip("\\")
    if not re.fullmatch(r"\\\\[^\\/]+\\.+", path):
        raise ConfigurationError(f"Invalid {label} UNC path: {value!r}")
    return path


def parse_drive_maps(value: str | None) -> list[DriveMapping]:
    """Import legacy text entries; the deployment UI now uses mapping rows."""
    result: list[DriveMapping] = []
    seen: set[str] = set()
    for entry in re.split(r"[;\r\n]+", value or ""):
        entry = entry.strip()
        if not entry:
            continue
        vpn_path, divider, restore_path = entry.partition("|")
        match = re.fullmatch(r"\s*([A-Za-z]):?\s*=\s*(.+?)\s*", vpn_path)
        if not match:
            raise ConfigurationError(
                f"Invalid drive mapping {entry!r}; use Z:=\\\\nas.example.com\\Share")
        letter = normalize_drive_letter(match.group(1))
        path = _unc_path(match.group(2), label="VPN")
        restore = _unc_path(restore_path, label="LAN restore") if divider else None
        if letter in seen:
            raise ConfigurationError(f"Drive {letter} is configured more than once")
        seen.add(letter)
        result.append(DriveMapping(letter, path, restore))
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

    @staticmethod
    def profile_age_seconds(letter: str) -> float | None:
        """Return the age of the user's persisted mapping profile, if any.

        Group Policy Drive Maps updates this per-user profile as it creates or
        changes a drive.  It is readable by a standard user, unlike the Group
        Policy Operational log, so the tray can safely use it at logon.
        """
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"Network\{letter[0]}") as key:
                _, _, last_write = winreg.QueryInfoKey(key)
        except FileNotFoundError:
            return None
        # Registry timestamps are 100 ns ticks since 1601-01-01 UTC.
        unix_seconds = (last_write - 116444736000000000) / 10_000_000
        return max(0.0, time.time() - unix_seconds)

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
                 state_path: Path, provider=None, *,
                 release_timeout: float = 5.0,
                 release_poll_interval: float = 0.1,
                 policy_quiet_seconds: float = 10.0,
                 policy_wait_timeout: float = 30.0,
                 policy_poll_interval: float = 0.25) -> None:
        self.mappings = tuple(mappings)
        self.state_path = state_path
        self.provider = provider or WindowsDriveProvider()
        self.release_timeout = release_timeout
        self.release_poll_interval = release_poll_interval
        self.policy_quiet_seconds = policy_quiet_seconds
        self.policy_wait_timeout = policy_wait_timeout
        self.policy_poll_interval = policy_poll_interval

    def _wait_for_recent_policy_update(self, letter: str) -> None:
        """Allow a just-updated Group Policy drive-map profile to settle first."""
        profile_age = getattr(self.provider, "profile_age_seconds", None)
        if not callable(profile_age):
            return
        deadline = time.monotonic() + self.policy_wait_timeout
        while True:
            age = profile_age(letter)
            if age is None or age >= self.policy_quiet_seconds:
                return
            if time.monotonic() >= deadline:
                raise BackendError(
                    f"Windows is still applying a recent drive-map policy for {letter}; "
                    "it was not remapped")
            time.sleep(self.policy_poll_interval)

    def _wait_until_unmapped(self, letter: str) -> None:
        """Do not reuse a letter until Windows confirms its connection is gone."""
        deadline = time.monotonic() + self.release_timeout
        while self.provider.current(letter) is not None:
            if time.monotonic() >= deadline:
                raise BackendError(
                    f"Windows is still releasing drive {letter}; it was not remapped")
            time.sleep(self.release_poll_interval)

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
        # A Group Policy Drive Maps update commonly runs at sign-in.  Let its
        # persisted user profile become quiet before capturing or replacing a
        # mapping, otherwise the two writers can race for the same letter.
        for mapping in self.mappings:
            self._wait_for_recent_policy_update(mapping.letter)
        previous = self._load()
        if previous is None:
            previous = []
            for mapping in self.mappings:
                current = self.provider.current(mapping.letter)
                persistent, username, saved_path = self.provider.saved_details(mapping.letter)
                previous.append(PreviousMapping(
                    # A remembered mapping is normally managed by Group Policy.  Prefer it
                    # to the currently connected drive and never remove its profile merely
                    # to substitute the VPN address for this session.
                    mapping.letter, mapping.restore_path or saved_path or current,
                    persistent if (current or saved_path) else bool(mapping.restore_path), username,
                    changed=(mapping.restore_path is not None or current is None or
                             current.casefold() != mapping.path.casefold())))
            # Save before changing anything so a crash can still be recovered.
            self._save(previous)
        else:
            by_letter = {item.letter: item for item in previous}
            updated = False
            for mapping in self.mappings:
                saved = by_letter.get(mapping.letter)
                if saved and mapping.restore_path and saved.path != mapping.restore_path:
                    replacement = replace(saved, path=mapping.restore_path,
                                          persistent=saved.persistent or True, changed=True)
                    previous[previous.index(saved)] = replacement
                    by_letter[mapping.letter] = replacement
                    updated = True
            if updated:
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
                if current:
                    # Disconnect the active connection only.  Passing CONNECT_UPDATE_PROFILE
                    # here would delete a remembered / Group Policy drive mapping.
                    self.provider.remove(mapping.letter, persistent=False)
                    self._wait_until_unmapped(mapping.letter)
                self.provider.add(mapping, persistent=False)
        except Exception:
            self.disconnect()
            raise

    def disconnect(self) -> None:
        # A deployment without configured drive mappings must never inspect a
        # leftover state file or call Windows networking APIs on disconnect.
        # This keeps the tray disconnect action a true no-op for machines that
        # do not use mapped drives.
        if not self.mappings:
            return
        previous = self._load()
        if previous is None:
            return
        configured = {mapping.letter: mapping for mapping in self.mappings}
        errors: list[str] = []
        for saved in reversed(previous):
            if not saved.changed:
                continue
            try:
                current = self.provider.current(saved.letter)
                target = configured.get(saved.letter)
                # Restore only a drive currently owned by this VPN.  If the
                # user removed it, Windows restored it itself, or another
                # process remapped the letter, it is no longer ours to change.
                # In particular, never recreate a missing short-name map.
                if (not saved.path or not target or not current or
                        current.casefold() != target.path.casefold()):
                    continue
                self.provider.remove(saved.letter, persistent=False)
                self._wait_until_unmapped(saved.letter)
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
