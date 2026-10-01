from __future__ import annotations

import json
import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .credentials import CloudCredentials
from .errors import ApiError
from .session import CloudCredentialSessionProvider


@dataclass(frozen=True)
class CloudController:
    device_id: str
    omada_id: str
    name: str
    model: str
    version: str
    connector_url: str
    status: int
    raw: dict[str, Any]


class CloudDiscoveryClient:
    cloud_manager = "https://use1-api-omada-cloud-manager.tplinkcloud.com"

    def __init__(self, credentials: CloudCredentials, *, timeout: float = 30):
        self.session = CloudCredentialSessionProvider(None, credentials=credentials, timeout=timeout)
        self.timeout = timeout
        self.user_ids: dict[str, str] = {}

    def _get(self, url: str, *, user_id: str | None = None) -> Any:
        request = urllib.request.Request(url, headers=self.session.cloud_headers(user_id=user_id))
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                envelope = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ApiError(f"Omada Cloud discovery failed: {exc}") from exc
        code = envelope.get("errorCode")
        if code != 0:
            raise ApiError(envelope.get("msg") or "Omada Cloud discovery failed", code=code)
        return envelope.get("result")

    @staticmethod
    def _items(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("data", "list", "items", "records"):
                if isinstance(result.get(key), list):
                    return result[key]
        raise ApiError("Omada Cloud returned an unexpected list response")

    def controllers(self) -> list[CloudController]:
        host = self._get(self.cloud_manager + "/api/v1/central/account/cloudaccess/host")
        api_url = str((host or {}).get("apiUrl", "")).rstrip("/")
        if not api_url:
            raise ApiError("Omada Cloud did not return its Cloud Access API host")
        result = self._get(api_url + "/api/v1/cloudaccess/organizations?currentPage=1&currentPageSize=100")
        controllers = []
        for item in self._items(result):
            device_id, omada_id = str(item.get("deviceId", "")), str(item.get("omadacId", ""))
            connector = str(item.get("connectorUrl") or item.get("guardUrl") or "").rstrip("/")
            if device_id and omada_id and connector:
                controllers.append(CloudController(
                    device_id, omada_id, str(item.get("deviceName") or item.get("alias") or device_id),
                    str(item.get("showModel") or item.get("deviceModel") or ""),
                    str(item.get("controllerVersion") or ""), connector, int(item.get("status", 0)), item,
                ))
        return controllers

    def user_id(self, controller: CloudController) -> str:
        if controller.device_id not in self.user_ids:
            root = f"{controller.connector_url}/omadac/{controller.device_id}/{controller.omada_id}/api/v2"
            result = self._get(root + "/current/user-detail")
            value = str((result or {}).get("id", ""))
            if not value:
                raise ApiError("The selected controller did not return the current user ID")
            self.user_ids[controller.device_id] = value
        return self.user_ids[controller.device_id]

    def sites(self, controller: CloudController) -> list[dict[str, Any]]:
        user_id = self.user_id(controller)
        root = f"{controller.connector_url}/omadac/{controller.device_id}/{controller.omada_id}/api/v2"
        return self._items(self._get(root + "/sites?currentPage=1&currentPageSize=100", user_id=user_id))

    def wireguard_servers(self, controller: CloudController, site_id: str) -> list[dict[str, Any]]:
        user_id = self.user_id(controller)
        path = (f"{controller.connector_url}/omadac/{controller.device_id}/openapi/v2/{controller.omada_id}/sites/"
                f"{urllib.parse.quote(site_id, safe='')}/vpn/client-to-site-vpn-servers?page=1&pageSize=100")
        return [item for item in self._items(self._get(path, user_id=user_id)) if item.get("vpnType") == 4]

    @staticmethod
    def _endpoint_from_gateway(server: dict[str, Any], gateway: dict[str, Any]) -> str:
        selected_ports: list[int] = []
        for value in server.get("wans") or []:
            try:
                selected_ports.append(int(str(value).split("_", 1)[0]))
            except (TypeError, ValueError):
                continue

        stats = gateway.get("portStats") or []
        ordered = ([item for port in selected_ports for item in stats if item.get("port") == port]
                   if selected_ports else list(stats))
        for item in ordered:
            ipv4 = item.get("wanPortIpv4Config") or {}
            ipv6 = item.get("wanPortIpv6Config") or {}
            for candidate in (ipv4.get("ip"), item.get("ip"), ipv6.get("addr")):
                value = str(candidate or "").split("/", 1)[0].strip()
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if not address.is_unspecified and not address.is_loopback and not address.is_link_local:
                    return value
        return ""

    def wireguard_endpoint(self, controller: CloudController, site_id: str,
                           server: dict[str, Any]) -> str:
        """Resolve the live address of the WAN selected by this WireGuard server."""
        user_id = self.user_id(controller)
        root = (f"{controller.connector_url}/omadac/{controller.device_id}/{controller.omada_id}"
                f"/api/v2/sites/{urllib.parse.quote(site_id, safe='')}")
        devices = self._items(self._get(
            root + "/grid/devices?currentPage=1&currentPageSize=100", user_id=user_id))
        gateways = [item for item in devices if str(item.get("type", "")).casefold() == "gateway"]
        for gateway in gateways:
            mac = str(gateway.get("mac") or "")
            if not mac:
                continue
            detail = self._get(root + "/gateways/" + urllib.parse.quote(mac, safe=""), user_id=user_id)
            endpoint = self._endpoint_from_gateway(server, detail or {})
            if endpoint:
                return endpoint
        return ""

    def wireguard_site_routes(self, controller: CloudController, site_id: str,
                              server: dict[str, Any]) -> tuple[str, ...]:
        """Resolve the LAN CIDRs selected in the WireGuard server configuration."""
        user_id = self.user_id(controller)
        root = (f"{controller.connector_url}/omadac/{controller.device_id}/{controller.omada_id}"
                f"/api/v2/sites/{urllib.parse.quote(site_id, safe='')}")
        result = self._get(
            root + "/setting/lan/networks?currentPage=1&currentPageSize=100", user_id=user_id)
        selected = {str(value) for value in server.get("networkList") or ()}
        routes: list[str] = []
        for network in self._items(result):
            network_id = str(network.get("id") or "")
            if selected and network_id not in selected:
                continue
            value = str(network.get("gatewaySubnet") or "").strip()
            if not value:
                continue
            try:
                route = str(ipaddress.ip_interface(value))
            except ValueError:
                continue
            if route not in routes:
                routes.append(route)
        return tuple(routes)

    def session_record(self, controller: CloudController) -> dict[str, str]:
        headers = self.session.cloud_headers(user_id=self.user_id(controller))
        return {
            "cookie": headers["Cookie"], "csrf_token": headers["csrf-token"],
            "user_id": headers["user-id"], "origin": headers["Origin"],
        }
