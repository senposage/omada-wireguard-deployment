from __future__ import annotations

import ipaddress

from .errors import ConfigurationError
from .models import WireGuardPeer, WireGuardServer


def _normalized_routes(values: tuple[str, ...]) -> tuple[str, ...]:
    try:
        return tuple(str(ipaddress.ip_network(value, strict=False)) for value in values)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid AllowedIPs entry: {exc}") from exc


def generate_config(
    server: WireGuardServer,
    peer: WireGuardPeer,
    *,
    endpoint_host: str,
    dns: str | None,
    route_mode: str = "site",
    custom_routes: tuple[str, ...] = (),
    site_routes: tuple[str, ...] = (),
    keepalive: int | None = None,
    mtu: int | None = None,
) -> str:
    if not peer.private_key or not peer.interface_ip or not server.public_key:
        raise ConfigurationError("Omada returned an incomplete WireGuard client")
    endpoint_host = endpoint_host.strip()
    if not endpoint_host:
        raise ConfigurationError("No WireGuard endpoint was resolved")
    if route_mode == "full":
        routes = ("0.0.0.0/0", "::/0")
    elif route_mode == "custom":
        routes = _normalized_routes(custom_routes)
    elif route_mode == "site":
        routes = _normalized_routes(peer.allowed_addresses or site_routes)
    else:
        raise ConfigurationError(f"Unknown route mode: {route_mode}")
    if not routes:
        raise ConfigurationError("No AllowedIPs routes are available")
    try:
        address = str(ipaddress.ip_interface(peer.interface_ip + "/32"))
    except ValueError as exc:
        raise ConfigurationError(f"Invalid client interface IP: {peer.interface_ip}") from exc
    host = f"[{endpoint_host}]" if ":" in endpoint_host and not endpoint_host.startswith("[") else endpoint_host
    lines = ["[Interface]", f"PrivateKey = {peer.private_key}", f"Address = {address}"]
    if dns:
        lines.append(f"DNS = {dns}")
    if mtu is not None:
        lines.append(f"MTU = {mtu}")
    lines.extend(["", "[Peer]", f"PublicKey = {server.public_key}"])
    if peer.pre_shared_key:
        lines.append(f"PresharedKey = {peer.pre_shared_key}")
    lines.extend([
        f"AllowedIPs = {', '.join(routes)}",
        f"Endpoint = {host}:{server.service_port}",
        f"PersistentKeepalive = {server.keep_alive if keepalive is None else keepalive}",
        "",
    ])
    return "\n".join(lines)
