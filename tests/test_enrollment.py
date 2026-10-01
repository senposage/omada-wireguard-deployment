import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from omada_wg.enrollment import EnrollmentService
from omada_wg.models import WireGuardPeer, WireGuardServer
from omada_wg.settings import DeploymentConfig
from omada_wg.state import EnrollmentState, StateStore


class FakeApi:
    def __init__(self, server):
        self.server = server
        self.created = 0
        self.deleted = None
        self.replaced = None

    def validate_session(self): pass
    def find_server(self): return self.server
    def create_client(self, server, name):
        self.created += 1
        peer = WireGuardPeer("new-peer", name, "10.0.8.3", "new-pub", "new-private")
        clients = (*server.clients, peer)
        raw_clients = [
            {"id": item.id, "name": item.name, "publicKey": item.public_key,
             "privateKey": item.private_key, "interfaceIp": item.interface_ip}
            for item in clients
        ]
        self.server = replace(server, clients=clients, raw={**server.raw, "clients": raw_clients})
        return self.server
    def delete_client(self, server, client_id):
        self.deleted = client_id
        return replace(server, clients=tuple(peer for peer in server.clients if peer.id != client_id))
    def replace_client(self, server, old_client_id, new_client_id, final_name):
        self.replaced = (old_client_id, new_client_id, final_name)
        clients = tuple(
            replace(peer, name=final_name) if peer.id == new_client_id else peer
            for peer in server.clients if peer.id != old_client_id)
        self.server = replace(server, clients=clients)
        return self.server


class FakeBackend:
    def __init__(self): self.config = None; self.removed = None; self.access = None
    def install_and_start(self, tunnel_name, config): self.config = config
    def remove(self, tunnel_name): self.removed = tunnel_name
    def configure_access(self, tunnel_name, **options): self.access = (tunnel_name, options)


class FailingBackend(FakeBackend):
    def install_and_start(self, tunnel_name, config):
        raise RuntimeError("simulated install failure")


class EnrollmentTests(unittest.TestCase):
    def test_existing_named_peer_is_replaced_and_state_saved(self):
        peer = WireGuardPeer("p1", "LAPTOP", "10.0.8.2", "pub", "private", allowed_addresses=("10.1.2.3/24",))
        server = WireGuardServer("s1", "DRKNET", "server-pub", 51820, 25, (peer,))
        with tempfile.TemporaryDirectory() as directory:
            cfg = DeploymentConfig("https://example", "d", "o", "site", server_name="DRKNET",
                                   endpoint_fallback="vpn.example", dns="10.1.2.1",
                                   site_routes=("10.1.2.3/24",),
                                   state_path=Path(directory) / "state.json")
            api, backend = FakeApi(server), FakeBackend()
            result = EnrollmentService(cfg, api, backend, StateStore(cfg.state_path)).enroll(name="laptop")
            self.assertEqual(result.client_id, "new-peer")
            self.assertEqual(api.created, 1)
            self.assertEqual(api.replaced, ("p1", "new-peer", "laptop"))
            self.assertIn("AllowedIPs = 10.1.2.0/24", backend.config)
            self.assertEqual(StateStore(cfg.state_path).load(), result)

    def test_uses_discovered_site_routes_without_changing_peer(self):
        peer = WireGuardPeer("p1", "LAPTOP", "10.0.8.2", "pub", "private")
        server = WireGuardServer("s1", "DRKNET", "server-pub", 51820, 25, (peer,))
        with tempfile.TemporaryDirectory() as directory:
            cfg = DeploymentConfig(
                "https://example", "d", "o", "site", server_name="DRKNET",
                endpoint_fallback="vpn.example", site_routes=("192.168.1.0/24",),
                state_path=Path(directory) / "state.json")
            api, backend = FakeApi(server), FakeBackend()
            EnrollmentService(cfg, api, backend, StateStore(cfg.state_path)).enroll(name="laptop")
            self.assertIn("AllowedIPs = 192.168.1.0/24", backend.config)

    def test_unenroll_deletes_peer_tunnel_and_state(self):
        peer = WireGuardPeer("p1", "LAPTOP", "10.0.8.2", "pub", "private")
        server = WireGuardServer("s1", "DRKNET", "server-pub", 51820, 25, (peer,))
        with tempfile.TemporaryDirectory() as directory:
            cfg = DeploymentConfig(
                "https://example", "d", "o", "site", server_name="DRKNET",
                endpoint_fallback="vpn.example", state_path=Path(directory) / "state.json")
            state = StateStore(cfg.state_path)
            state.save(EnrollmentState("s1", "p1", "LAPTOP", "omada"))
            api, backend = FakeApi(server), FakeBackend()
            removed = EnrollmentService(cfg, api, backend, state).unenroll(name="laptop")
            self.assertTrue(removed)
            self.assertEqual(api.deleted, "p1")
            self.assertEqual(backend.removed, "omada")
            self.assertIsNone(state.load())

    def test_new_peer_is_rolled_back_when_install_fails(self):
        created = WireGuardPeer(
            "new-peer", "LAPTOP", "10.0.8.3", "pub", "private",
            allowed_addresses=("192.168.1.1/24",))
        empty = WireGuardServer("s1", "DRKNET", "server-pub", 51820, 25, ())

        class CreatingApi(FakeApi):
            def create_client(self, server, name):
                self.created += 1
                return replace(server, clients=(created,), raw={"id": "s1", "clients": [
                    {"id": "new-peer", "name": name}]})

        with tempfile.TemporaryDirectory() as directory:
            cfg = DeploymentConfig(
                "https://example", "d", "o", "site", server_name="DRKNET",
                endpoint_fallback="vpn.example", state_path=Path(directory) / "state.json")
            api, backend = CreatingApi(empty), FailingBackend()
            with self.assertRaisesRegex(RuntimeError, "simulated install failure"):
                EnrollmentService(cfg, api, backend, StateStore(cfg.state_path)).enroll(name="laptop")
            self.assertEqual(api.deleted, "new-peer")
            self.assertEqual(backend.removed, "omada")
            self.assertIsNone(StateStore(cfg.state_path).load())


if __name__ == "__main__":
    unittest.main()
