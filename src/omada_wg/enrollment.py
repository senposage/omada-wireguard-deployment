from __future__ import annotations

import secrets

from .api import OmadaClient
from .backend import WireGuardBackend
from .configgen import generate_config
from .errors import ConfigurationError, EnrollmentError
from .models import WireGuardPeer, WireGuardServer
from .settings import DeploymentConfig
from .state import EnrollmentState, StateStore
from .identity import client_name


class EnrollmentService:
    def __init__(self, config: DeploymentConfig, api: OmadaClient, backend: WireGuardBackend, state: StateStore):
        self.config = config
        self.api = api
        self.backend = backend
        self.state = state

    def _find_existing(self, server: WireGuardServer, name: str) -> WireGuardPeer | None:
        saved = self.state.load()
        if saved and saved.server_id == server.id:
            match = next((p for p in server.clients if p.id == saved.client_id), None)
            if match:
                return match
        named = [p for p in server.clients if p.name.casefold() == name.casefold()]
        if len(named) > 1:
            raise EnrollmentError(f"Multiple Omada clients are named {name!r}; refusing to guess")
        return named[0] if named else None

    @staticmethod
    def _replacement_name(name: str, server: WireGuardServer) -> str:
        used = {peer.name.casefold() for peer in server.clients}
        for _ in range(20):
            candidate = f"{name[:40]}_new_{secrets.token_hex(4)}"
            if candidate.casefold() not in used:
                return candidate
        raise EnrollmentError("Could not allocate a unique temporary Omada client name")

    def _render(self, server: WireGuardServer, peer: WireGuardPeer) -> str:
        endpoint = self.config.endpoint_fallback
        if not endpoint:
            raise ConfigurationError("No WireGuard endpoint was resolved")
        return generate_config(
            server, peer, endpoint_host=endpoint, dns=self.config.dns,
            route_mode=self.config.route_mode, custom_routes=self.config.allowed_ips,
            site_routes=self.config.site_routes,
            keepalive=self.config.keepalive, mtu=self.config.mtu,
        )

    def enroll(self, *, name: str | None = None, install: bool = True) -> EnrollmentState:
        name = name or client_name(self.config.client_name_mode, self.config.client_custom_name)
        self.api.validate_session()
        server = self.api.find_server()
        stale_peer = self._find_existing(server, name)
        previous_config = self._render(server, stale_peer) if stale_peer and install else None
        create_name = self._replacement_name(name, server) if stale_peer else name
        peer = None
        created_this_run = False
        server = self.api.create_client(server, create_name)
        matches = [p for p in server.clients if p.name.casefold() == create_name.casefold()]
        if len(matches) != 1:
            raise EnrollmentError("Omada did not return exactly one newly created client")
        peer = matches[0]
        created_this_run = True
        rollback_server = server
        try:
            rendered = self._render(server, peer)
            if install:
                self.backend.install_and_start(self.config.tunnel_name, rendered)
                self.backend.configure_access(
                    self.config.tunnel_name,
                    desktop_shortcut=self.config.desktop_shortcut,
                    launch_manager=False,
                    start_with_windows=self.config.start_with_windows,
                )
            if stale_peer:
                server = self.api.replace_client(server, stale_peer.id, peer.id, name)
                replacement = [item for item in server.clients
                               if item.public_key == peer.public_key and
                               item.name.casefold() == name.casefold()]
                if len(replacement) != 1:
                    raise EnrollmentError("Omada did not return the finalized replacement client")
                peer = replacement[0]
            result = EnrollmentState(server.id, peer.id, peer.name, self.config.tunnel_name)
            self.state.save(result)
            return result
        except Exception as original:
            cleanup_errors: list[str] = []
            if created_this_run:
                if install:
                    try:
                        if previous_config:
                            self.backend.install_and_start(self.config.tunnel_name, previous_config)
                            self.backend.configure_access(
                                self.config.tunnel_name,
                                desktop_shortcut=self.config.desktop_shortcut,
                                launch_manager=False,
                                start_with_windows=self.config.start_with_windows,
                            )
                        else:
                            self.backend.remove(self.config.tunnel_name)
                    except Exception as exc:
                        cleanup_errors.append(f"local tunnel cleanup failed: {exc}")
                try:
                    self.api.delete_client(rollback_server, peer.id)
                except Exception as exc:
                    cleanup_errors.append(f"Omada peer cleanup failed: {exc}")
            if cleanup_errors:
                raise EnrollmentError(f"{original}; rollback incomplete: {'; '.join(cleanup_errors)}") from original
            raise

    def unenroll(self, *, name: str | None = None) -> bool:
        name = name or client_name(self.config.client_name_mode, self.config.client_custom_name)
        self.api.validate_session()
        server = self.api.find_server()
        saved = self.state.load()
        peer = None
        if saved:
            peer = next((item for item in server.clients if item.id == saved.client_id), None)
        if peer is None:
            named = [item for item in server.clients if item.name.casefold() == name.casefold()]
            if len(named) > 1:
                raise EnrollmentError(f"Multiple Omada clients are named {name!r}; refusing to guess")
            peer = named[0] if named else None
        if peer is not None:
            self.api.delete_client(server, peer.id)
        self.backend.remove(self.config.tunnel_name)
        self.state.clear()
        return peer is not None
