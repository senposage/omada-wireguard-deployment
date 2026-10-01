from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .drive_mapping import DriveMapping, normalize_drive_letter
from .errors import ConfigurationError


@dataclass(frozen=True)
class DeploymentConfig:
    connector_base_url: str
    device_id: str
    omada_id: str
    site_id: str
    user_id: str | None = None
    server_id: str | None = None
    server_name: str | None = None
    endpoint_fallback: str | None = None
    dns: str | None = None
    route_mode: str = "site"
    allowed_ips: tuple[str, ...] = ()
    site_routes: tuple[str, ...] = ()
    keepalive: int | None = None
    mtu: int | None = None
    tunnel_name: str = "omada"
    client_name_mode: str = "computer_user"
    client_custom_name: str | None = None
    state_path: Path = Path("omada-wg-state.json")
    write_enabled: bool = False
    session_file: Path | None = field(default=None, repr=False)
    credentials_file: Path | None = field(default=None, repr=False)
    credential_key: str | None = field(default=None, repr=False)
    wireguard_msi_dir: Path | None = None
    controller_name: str | None = None
    site_name: str | None = None
    desktop_shortcut: bool = True
    launch_manager: bool = True
    start_with_windows: bool = True
    drive_maps: tuple[DriveMapping, ...] = ()
    disconnect_on_office_dns: bool = False
    remove_credentials_after_enroll: bool = False

    @classmethod
    def load(cls, path: str | Path) -> "DeploymentConfig":
        source = Path(path)
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"Cannot read deployment config: {exc}") from exc
        if not data.get("controller_name") and not data.get("device_id"):
            raise ConfigurationError("Set controller_name or device_id")
        if not data.get("site_name") and not data.get("site_id"):
            raise ConfigurationError("Set site_name or site_id")
        if not data.get("server_id") and not data.get("server_name"):
            raise ConfigurationError("Set server_id or server_name")
        mode = data.get("route_mode", "site")
        if mode not in {"site", "full", "custom"}:
            raise ConfigurationError("route_mode must be site, full, or custom")
        if mode == "custom" and not data.get("allowed_ips"):
            raise ConfigurationError("custom route_mode requires allowed_ips")
        name_mode = data.get("client_name_mode", "computer_user")
        if name_mode not in {"computer_user", "computer", "custom"}:
            raise ConfigurationError("client_name_mode must be computer_user, computer, or custom")
        if name_mode == "custom" and not data.get("client_custom_name"):
            raise ConfigurationError("custom client_name_mode requires client_custom_name")
        drive_maps: list[DriveMapping] = []
        seen_drives: set[str] = set()
        for item in data.get("drive_maps") or ():
            try:
                letter = normalize_drive_letter(str(item["letter"]))
                remote_path = str(item["path"]).strip().rstrip("\\")
                restore_path = str(item.get("restore_path") or "").strip().rstrip("\\") or None
            except (KeyError, TypeError) as exc:
                raise ConfigurationError("Each drive mapping requires letter and path") from exc
            if not re.fullmatch(r"\\\\[^\\/]+\\.+", remote_path):
                raise ConfigurationError(f"Drive {letter} requires a UNC path")
            if restore_path and not re.fullmatch(r"\\\\[^\\/]+\\.+", restore_path):
                raise ConfigurationError(f"Drive {letter} requires a UNC LAN restore path")
            if letter in seen_drives:
                raise ConfigurationError(f"Drive {letter} is configured more than once")
            seen_drives.add(letter)
            drive_maps.append(DriveMapping(letter, remote_path, restore_path))
        state_path = Path(os.path.expandvars(data.get("state_path", "omada-wg-state.json")))
        if not state_path.is_absolute():
            state_path = source.parent / state_path
        return cls(
            connector_base_url=str(data.get("connector_base_url") or "").rstrip("/"),
            device_id=str(data.get("device_id") or ""), omada_id=str(data.get("omada_id") or ""),
            site_id=str(data.get("site_id") or ""),
            user_id=data.get("user_id"),
            server_id=data.get("server_id"), server_name=data.get("server_name"),
            endpoint_fallback=data.get("endpoint_fallback"), dns=data.get("dns"),
            route_mode=mode, allowed_ips=tuple(data.get("allowed_ips") or ()),
            site_routes=tuple(data.get("site_routes") or ()),
            keepalive=data.get("keepalive"), mtu=data.get("mtu"),
            tunnel_name=data.get("tunnel_name", "omada"), state_path=state_path,
            client_name_mode=name_mode, client_custom_name=data.get("client_custom_name"),
            write_enabled=bool(data.get("write_enabled", False)),
            session_file=(source.parent / data["session_file"]).resolve()
            if data.get("session_file") and not Path(data["session_file"]).is_absolute()
            else (Path(data["session_file"]) if data.get("session_file") else None),
            credentials_file=(source.parent / data["credentials_file"]).resolve()
            if data.get("credentials_file") and not Path(data["credentials_file"]).is_absolute()
            else (Path(data["credentials_file"]) if data.get("credentials_file") else None),
            credential_key=data.get("credential_key"),
            controller_name=data.get("controller_name"), site_name=data.get("site_name"),
            desktop_shortcut=bool(data.get("desktop_shortcut", True)),
            launch_manager=bool(data.get("launch_manager", True)),
            start_with_windows=bool(data.get("start_with_windows", True)),
            drive_maps=tuple(drive_maps),
            disconnect_on_office_dns=bool(data.get("disconnect_on_office_dns", False)),
            remove_credentials_after_enroll=bool(data.get("remove_credentials_after_enroll", False)),
            wireguard_msi_dir=(source.parent / data["wireguard_msi_dir"]).resolve()
            if data.get("wireguard_msi_dir") and not Path(data["wireguard_msi_dir"]).is_absolute()
            else (Path(data["wireguard_msi_dir"]) if data.get("wireguard_msi_dir") else None),
        )
