from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, TypeVar

from .cloud_discovery import CloudController, CloudDiscoveryClient
from .errors import EnrollmentError
from .settings import DeploymentConfig


T = TypeVar("T")


def _select(items: list[T], *, name: str | None, identifier: str | None,
            item_name: Callable[[T], str], item_id: Callable[[T], str], label: str) -> T:
    named = [item for item in items if name and item_name(item).casefold() == name.casefold()]
    if len(named) == 1:
        return named[0]
    pool = named if named else items
    identified = [item for item in pool if identifier and item_id(item) == identifier]
    if len(identified) == 1:
        return identified[0]
    selector = name or identifier or "(missing selector)"
    raise EnrollmentError(f"Could not uniquely rediscover the configured {label}: {selector}")


def resolve_runtime(config: DeploymentConfig, discovery: CloudDiscoveryClient) -> DeploymentConfig:
    """Freshly discover all Omada routing/session identifiers for an installer run."""
    controller = _select(
        discovery.controllers(), name=config.controller_name, identifier=config.device_id,
        item_name=lambda item: item.name, item_id=lambda item: item.device_id, label="controller")
    sites = discovery.sites(controller)
    site = _select(
        sites, name=config.site_name, identifier=config.site_id,
        item_name=lambda item: str(item.get("name") or ""),
        item_id=lambda item: str(item.get("id") or item.get("siteId") or ""), label="site")
    site_id = str(site.get("id") or site.get("siteId") or "")
    servers = discovery.wireguard_servers(controller, site_id)
    server = _select(
        servers, name=config.server_name, identifier=config.server_id,
        item_name=lambda item: str(item.get("name") or ""),
        item_id=lambda item: str(item.get("id") or ""), label="WireGuard server")
    user_id = discovery.user_id(controller)
    endpoint = discovery.wireguard_endpoint(controller, site_id, server) or config.endpoint_fallback
    if not endpoint:
        raise EnrollmentError("The selected WireGuard WAN did not report an endpoint")
    discovery.session.set_user_id(user_id)
    site_routes = discovery.wireguard_site_routes(controller, site_id, server)
    return replace(
        config,
        connector_base_url=controller.connector_url,
        controller_name=controller.name,
        device_id=controller.device_id,
        omada_id=controller.omada_id,
        user_id=user_id,
        site_id=site_id,
        site_name=str(site.get("name") or ""),
        server_id=str(server.get("id") or ""),
        server_name=str(server.get("name") or ""),
        endpoint_fallback=endpoint,
        site_routes=site_routes,
    )
