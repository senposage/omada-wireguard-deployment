import unittest

from omada_wg.cloud_discovery import CloudDiscoveryClient


class CloudEndpointTests(unittest.TestCase):
    def test_uses_the_wan_port_selected_by_wireguard(self):
        server = {"wans": ["2_random-id"]}
        gateway = {"portStats": [
            {"port": 1, "wanPortIpv4Config": {"ip": "198.51.100.1"}},
            {"port": 2, "wanPortIpv4Config": {"ip": "203.0.113.9"}},
        ]}
        self.assertEqual(
            CloudDiscoveryClient._endpoint_from_gateway(server, gateway), "203.0.113.9")

    def test_ignores_unusable_selected_wan_addresses(self):
        server = {"wans": ["1_random-id"]}
        gateway = {"portStats": [
            {"port": 1, "wanPortIpv4Config": {"ip": "0.0.0.0"}, "ip": "169.254.1.1"},
        ]}
        self.assertEqual(CloudDiscoveryClient._endpoint_from_gateway(server, gateway), "")


if __name__ == "__main__":
    unittest.main()
