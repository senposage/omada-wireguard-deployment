import unittest
import json
import tempfile
from pathlib import Path

from omada_wg.bootstrap import resolve_runtime
from omada_wg.cloud_discovery import CloudController
from omada_wg.settings import DeploymentConfig


class FakeSession:
    def __init__(self):
        self.user_id = ""

    def set_user_id(self, value):
        self.user_id = value


class FakeDiscovery:
    def __init__(self):
        self.session = FakeSession()
        self.controller = CloudController("fresh-device", "fresh-omada", "Office Controller", "", "",
                                          "https://fresh-connector", 1, {})

    def controllers(self):
        return [self.controller]

    def sites(self, controller):
        return [{"id": "fresh-site", "name": "Main Office"}]

    def wireguard_servers(self, controller, site_id):
        return [{"id": "fresh-server", "name": "Staff VPN", "vpnType": 4}]

    def user_id(self, controller):
        return "fresh-user"

    def wireguard_endpoint(self, controller, site_id, server):
        return "203.0.113.44"

    def wireguard_site_routes(self, controller, site_id, server):
        return ("192.168.10.0/24",)


class RuntimeBootstrapTests(unittest.TestCase):
    def test_rediscovers_runtime_values_by_selected_names(self):
        config = DeploymentConfig(
            "https://stale", "stale-device", "stale-omada", "stale-site",
            user_id="stale-user", server_id="stale-server", server_name="Staff VPN",
            endpoint_fallback="198.51.100.1", controller_name="Office Controller",
            site_name="Main Office")
        discovery = FakeDiscovery()
        resolved = resolve_runtime(config, discovery)
        self.assertEqual(resolved.connector_base_url, "https://fresh-connector")
        self.assertEqual(resolved.device_id, "fresh-device")
        self.assertEqual(resolved.omada_id, "fresh-omada")
        self.assertEqual(resolved.site_id, "fresh-site")
        self.assertEqual(resolved.server_id, "fresh-server")
        self.assertEqual(resolved.user_id, "fresh-user")
        self.assertEqual(resolved.endpoint_fallback, "203.0.113.44")
        self.assertEqual(resolved.site_routes, ("192.168.10.0/24",))
        self.assertEqual(discovery.session.user_id, "fresh-user")

    def test_package_config_can_load_with_names_and_no_runtime_ids(self):
        value = {
            "controller_name": "Office Controller", "site_name": "Main Office",
            "server_name": "Staff VPN", "route_mode": "site",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deployment.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            config = DeploymentConfig.load(path)
        self.assertEqual(config.controller_name, "Office Controller")
        self.assertEqual(config.device_id, "")
        self.assertEqual(config.site_id, "")

    def test_package_config_loads_a_separate_office_dns_suffix(self):
        value = {
            "controller_name": "Office Controller", "site_name": "Main Office",
            "server_name": "Staff VPN", "route_mode": "site",
            "office_dns_suffix": "OFFICE.example.local.",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deployment.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            config = DeploymentConfig.load(path)
        self.assertEqual(config.office_dns_suffix, "office.example.local")


if __name__ == "__main__":
    unittest.main()
