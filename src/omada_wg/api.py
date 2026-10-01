from __future__ import annotations

import copy
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .errors import ApiError, AuthenticationError, ConfigurationError
from .models import WireGuardServer
from .keys import generate_keypair
from .session import OmadaSessionProvider
from .settings import DeploymentConfig


class OmadaClient:
    def __init__(self, config: DeploymentConfig, session: OmadaSessionProvider, *, timeout: float = 20):
        self.config = config
        self.session = session
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None,
                 *, _refreshed: bool = False) -> Any:
        url = self.config.connector_base_url + path
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = self.session.headers(vpn_request="/vpn/" in path)
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                envelope = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ApiError(f"Omada request failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ApiError(f"Omada request failed: {exc}") from exc
        code = envelope.get("errorCode")
        if code == -1200:
            if not _refreshed and self.session.refresh():
                return self._request(method, path, payload, _refreshed=True)
            raise AuthenticationError("Omada session is logged out or expired")
        if code != 0:
            raise ApiError(envelope.get("msg") or envelope.get("errorMsg") or "Omada API error", code=code)
        return envelope.get("result")

    def validate_session(self) -> None:
        c = self.config
        self._request("GET", f"/omadac/{c.device_id}/{c.omada_id}/api/v2/current/user-detail")

    def _vpn_path(self, suffix: str = "") -> str:
        c = self.config
        return f"/omadac/{c.device_id}/openapi/v2/{c.omada_id}/sites/{c.site_id}/vpn/client-to-site-vpn-servers{suffix}"

    @staticmethod
    def _items(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("data", "list", "items", "records"):
                if isinstance(result.get(key), list):
                    return result[key]
        raise ApiError("Unexpected Omada list response shape")

    def list_servers(self) -> list[dict[str, Any]]:
        result = self._request("GET", self._vpn_path("?page=1&pageSize=100"))
        return [item for item in self._items(result) if item.get("vpnType") == 4]

    def find_server(self) -> WireGuardServer:
        c = self.config
        candidates = self.list_servers()
        matches = [x for x in candidates if (c.server_id and x.get("id") == c.server_id) or
                   (not c.server_id and c.server_name and x.get("name") == c.server_name)]
        if len(matches) != 1:
            raise ApiError(f"Expected exactly one WireGuard server, found {len(matches)}")
        return self.get_server(str(matches[0]["id"]))

    def get_server(self, server_id: str) -> WireGuardServer:
        result = self._request("GET", self._vpn_path("/" + urllib.parse.quote(server_id, safe="")))
        if isinstance(result, dict) and isinstance(result.get("data"), dict):
            result = result["data"]
        if not isinstance(result, dict):
            raise ApiError("Unexpected Omada server response shape")
        return WireGuardServer.from_api(result)

    _PATCH_FIELDS = (
        "vpnType", "name", "status", "wans", "networkType", "networkList",
        "privateKey", "publicKey", "clients", "customServer", "ipPoolType",
        "mtu", "keepAlive", "dnsStatus", "dns1", "dns2", "ipPool",
        "servicePort", "id",
    )

    @classmethod
    def _server_patch_payload(cls, raw: dict[str, Any]) -> dict[str, Any]:
        payload = {key: copy.deepcopy(raw[key]) for key in cls._PATCH_FIELDS if key in raw}
        for client in payload.get("clients", []):
            client.pop("id", None)
        return payload

    @staticmethod
    def _next_interface_ip(server: WireGuardServer) -> str:
        pool = server.raw.get("ipPool") or {}
        try:
            network = ipaddress.ip_network(f"{pool['ip']}/{pool['mask']}", strict=False)
            reserved = {ipaddress.ip_address(str(pool["ip"]))}
            reserved.update(ipaddress.ip_address(peer.interface_ip) for peer in server.clients)
        except (KeyError, ValueError) as exc:
            raise ConfigurationError("Omada returned an invalid WireGuard IP pool") from exc
        for candidate in network.hosts():
            if candidate not in reserved:
                return str(candidate)
        raise ConfigurationError("The WireGuard client IP pool is full")

    def create_client(self, server: WireGuardServer, name: str) -> WireGuardServer:
        """Reproduce the server-level Apply request captured from Omada's UI."""
        c = self.config
        if not c.write_enabled:
            raise ConfigurationError("Client creation is disabled; set write_enabled only for a dummy controller")
        if not name or not name.replace("_", "").isalnum():
            raise ConfigurationError("Client name may contain only letters, numbers, and underscores")
        private_key, public_key = generate_keypair()
        payload = self._server_patch_payload(server.raw)
        client = {
            "name": name,
            "publicKey": public_key,
            "privateKey": private_key,
            "interfaceIp": self._next_interface_ip(server),
        }
        payload["clients"] = [*payload.get("clients", []), client]
        self._request("PATCH", self._vpn_path("/" + urllib.parse.quote(server.id, safe="")), payload)
        return self.get_server(server.id)

    def delete_client(self, server: WireGuardServer, client_id: str) -> WireGuardServer:
        """Remove one client through Omada's server-level Apply contract."""
        if not self.config.write_enabled:
            raise ConfigurationError("Client deletion is disabled")
        existing = list(server.raw.get("clients") or [])
        remaining = [client for client in existing if str(client.get("id", "")) != client_id]
        if len(remaining) != len(existing) - 1:
            raise ApiError("Refusing delete: client ID was missing or non-unique")
        payload = self._server_patch_payload(server.raw)
        payload["clients"] = remaining
        for client in payload["clients"]:
            client.pop("id", None)
        self._request("PATCH", self._vpn_path("/" + urllib.parse.quote(server.id, safe="")), payload)
        updated = self.get_server(server.id)
        if any(peer.id == client_id for peer in updated.clients):
            raise ApiError("Omada accepted the PATCH but the client still exists")
        return updated

    def replace_client(self, server: WireGuardServer, old_client_id: str,
                       new_client_id: str, final_name: str) -> WireGuardServer:
        """Atomically remove a stale peer and give its verified replacement the final name."""
        if not self.config.write_enabled:
            raise ConfigurationError("Client replacement is disabled")
        existing = list(server.raw.get("clients") or [])
        old_matches = [client for client in existing if str(client.get("id", "")) == old_client_id]
        new_matches = [client for client in existing if str(client.get("id", "")) == new_client_id]
        if len(old_matches) != 1 or len(new_matches) != 1 or old_client_id == new_client_id:
            raise ApiError("Refusing replacement: old or new client ID was missing or non-unique")
        replacement_key = str(new_matches[0].get("publicKey", ""))
        remaining = []
        for client in existing:
            if str(client.get("id", "")) == old_client_id:
                continue
            item = copy.deepcopy(client)
            if str(item.get("id", "")) == new_client_id:
                item["name"] = final_name
            remaining.append(item)
        payload = self._server_patch_payload(server.raw)
        payload["clients"] = remaining
        for client in payload["clients"]:
            client.pop("id", None)
        self._request("PATCH", self._vpn_path("/" + urllib.parse.quote(server.id, safe="")), payload)
        updated = self.get_server(server.id)
        matches = [peer for peer in updated.clients
                   if peer.public_key == replacement_key and peer.name.casefold() == final_name.casefold()]
        if len(matches) != 1 or any(peer.id == old_client_id for peer in updated.clients):
            raise ApiError("Omada accepted the replacement PATCH but did not commit it exactly once")
        return updated

    def verify_client_write_cycle(self, name: str) -> str:
        """Create and then remove one uniquely named peer on an explicit test controller."""
        self.validate_session()
        before = self.find_server()
        if any(peer.name.casefold() == name.casefold() for peer in before.clients):
            raise ApiError(f"A client named {name!r} already exists")
        created_server = self.create_client(before, name)
        previous_ids = {peer.id for peer in before.clients}
        created = [peer for peer in created_server.clients
                   if peer.id not in previous_ids and peer.name.casefold() == name.casefold()]
        if len(created) != 1 or not created[0].id:
            raise ApiError("Create PATCH did not yield exactly one identifiable new client")
        client_id = created[0].id
        try:
            self.delete_client(created_server, client_id)
        except Exception as exc:
            raise ApiError(f"Created test client {client_id}, but automatic cleanup failed: {exc}") from exc
        return client_id
