from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .credentials import CloudCredentials, PortableCredentialStore
from .drive_mapping import DriveMapping
from .errors import EnrollmentError


@dataclass(frozen=True)
class DeploymentTarget:
    device_id: str
    omada_id: str
    user_id: str
    connector_url: str
    controller_name: str = ""


def routes(mode: str, value: str | None) -> list[str]:
    if mode != "custom":
        return []
    entries = [entry.strip() for entry in (value or "").split(",") if entry.strip()]
    if not entries:
        raise EnrollmentError("Custom routing requires at least one IP address or network")
    try:
        return [str(ipaddress.ip_network(entry, strict=False)) for entry in entries]
    except ValueError as exc:
        raise EnrollmentError(f"Invalid custom route: {exc}") from exc


def write_deployment(output: Path, target: DeploymentTarget,
                     site: dict[str, Any], server: dict[str, Any], credentials: CloudCredentials,
                     *, route_mode: str = "site", allowed_ips: list[str] | None = None,
                     endpoint: str, dns: str | None = None, keepalive: int | None = None,
                     mtu: int | None = None, tunnel_name: str = "omada",
                     client_name_mode: str = "computer_user",
                     client_custom_name: str | None = None,
                     desktop_shortcut: bool = True, launch_manager: bool = True,
                     start_with_windows: bool = True,
                     drive_maps: list[DriveMapping] | None = None,
                     disconnect_on_office_dns: bool = False,
                     office_dns_suffix: str | None = None,
                     remove_credentials_after_enroll: bool = False) -> Path:
    site_id = str(site.get("id") or site.get("siteId") or "")
    if not site_id:
        raise EnrollmentError("Selected site did not contain an ID")
    output = output.resolve()
    credentials_path = output.with_suffix(".credentials.bin")
    key = PortableCredentialStore.generate_key()
    PortableCredentialStore(credentials_path, key).save(credentials)
    deployment = {
        "connector_base_url": target.connector_url,
        "controller_name": target.controller_name,
        "device_id": target.device_id,
        "omada_id": target.omada_id,
        "site_id": site_id,
        "site_name": str(site.get("name") or ""),
        "server_id": str(server["id"]),
        "server_name": server.get("name", ""),
        "endpoint_fallback": endpoint,
        "dns": dns,
        "route_mode": route_mode,
        "allowed_ips": allowed_ips or [],
        "site_routes": [],
        "keepalive": keepalive,
        "mtu": mtu,
        "tunnel_name": tunnel_name,
        "client_name_mode": client_name_mode,
        "client_custom_name": client_custom_name,
        "desktop_shortcut": desktop_shortcut,
        "launch_manager": launch_manager,
        "start_with_windows": start_with_windows,
        "drive_maps": [
            {"letter": mapping.letter, "path": mapping.path,
             **({"restore_path": mapping.restore_path} if mapping.restore_path else {})}
            for mapping in (drive_maps or [])
        ],
        "disconnect_on_office_dns": disconnect_on_office_dns,
        "office_dns_suffix": office_dns_suffix,
        "remove_credentials_after_enroll": remove_credentials_after_enroll,
        "state_path": r"%ProgramData%\OmadaWireGuard\enrollment.json",
        "credentials_file": credentials_path.name,
        "credential_key": PortableCredentialStore.encode_key(key),
        "wireguard_msi_dir": "wireguard",
        "write_enabled": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(deployment, indent=2) + "\n", encoding="utf-8")
    return output
