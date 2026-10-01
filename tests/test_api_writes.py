import unittest
from dataclasses import replace

from omada_wg.api import OmadaClient
from omada_wg.models import WireGuardPeer, WireGuardServer
from omada_wg.settings import DeploymentConfig


class Session:
    def headers(self, *, vpn_request=False): return {}


class WriteCycleClient(OmadaClient):
    def __init__(self):
        config = DeploymentConfig("https://example", "d", "o", "site", server_id="s",
                                  write_enabled=True)
        super().__init__(config, Session())
        self.peer = WireGuardPeer("new-id", "probe", "10.0.0.2", "pub", "priv", allowed_addresses=("10.1.0.0/16",))
        self.server = WireGuardServer("s", "server", "spub", 51820, 25, (), raw={"id": "s", "clients": []})
        self.deleted = None

    def validate_session(self): pass
    def find_server(self): return self.server
    def create_client(self, server, name):
        self.peer = replace(self.peer, name=name)
        return replace(server, clients=(self.peer,), raw={"id": "s", "clients": [{"id": "new-id", "name": name}]})
    def delete_client(self, server, client_id):
        self.deleted = client_id
        return replace(server, clients=())


class WriteCycleTests(unittest.TestCase):
    def test_create_then_delete(self):
        client = WriteCycleClient()
        self.assertEqual(client.verify_client_write_cycle("probe"), "new-id")
        self.assertEqual(client.deleted, "new-id")

    def test_selects_first_free_pool_address(self):
        peer = WireGuardPeer("p", "old", "10.0.8.2", "pub", "priv")
        server = WireGuardServer("s", "server", "spub", 51820, 25, (peer,),
                                 raw={"ipPool": {"ip": "10.0.8.1", "mask": 29}})
        self.assertEqual(OmadaClient._next_interface_ip(server), "10.0.8.3")

    def test_patch_payload_strips_client_ids_and_unknown_fields(self):
        raw = {"id": "server", "vpnType": 4, "featureDescription": ["ignore"],
               "clients": [{"id": "peer", "name": "one"}]}
        payload = OmadaClient._server_patch_payload(raw)
        self.assertNotIn("featureDescription", payload)
        self.assertNotIn("id", payload["clients"][0])

    def test_create_does_not_set_overlapping_controller_allowed_addresses(self):
        config = DeploymentConfig(
            "https://example", "d", "o", "site", server_id="s", write_enabled=True,
            site_routes=("192.168.1.1/24",))
        server = WireGuardServer(
            "s", "server", "spub", 51820, 25, (),
            raw={"id": "s", "vpnType": 4, "clients": [],
                 "ipPool": {"ip": "10.0.8.1", "mask": 24}})

        class CaptureClient(OmadaClient):
            def _request(self, method, path, payload=None, **kwargs):
                self.payload = payload
                return {}

            def get_server(self, server_id):
                return server

        client = CaptureClient(config, Session())
        client.create_client(server, "NEW_CLIENT")
        created = client.payload["clients"][-1]
        self.assertNotIn("allowedAddress", created)
        self.assertNotIn("allowedAddressStatus", created)

    def test_replace_removes_old_peer_and_renames_verified_new_peer(self):
        config = DeploymentConfig(
            "https://example", "d", "o", "site", server_id="s", write_enabled=True)
        old = WireGuardPeer("old", "LAPTOP", "10.0.8.2", "old-pub", "old-private")
        new = WireGuardPeer("new", "LAPTOP_new_1234", "10.0.8.3", "new-pub", "new-private")
        raw_clients = [
            {"id": "old", "name": old.name, "interfaceIp": old.interface_ip,
             "publicKey": old.public_key, "privateKey": old.private_key},
            {"id": "new", "name": new.name, "interfaceIp": new.interface_ip,
             "publicKey": new.public_key, "privateKey": new.private_key},
        ]
        server = WireGuardServer(
            "s", "server", "spub", 51820, 25, (old, new),
            raw={"id": "s", "vpnType": 4, "clients": raw_clients})

        class CaptureClient(OmadaClient):
            def _request(self, method, path, payload=None, **kwargs):
                self.payload = payload
                return {}

            def get_server(self, server_id):
                final = replace(new, name="LAPTOP")
                return replace(server, clients=(final,))

        client = CaptureClient(config, Session())
        updated = client.replace_client(server, "old", "new", "LAPTOP")
        self.assertEqual([item["name"] for item in client.payload["clients"]], ["LAPTOP"])
        self.assertNotIn("id", client.payload["clients"][0])
        self.assertEqual([peer.name for peer in updated.clients], ["LAPTOP"])


if __name__ == "__main__":
    unittest.main()
