import unittest

from omada_wg.configgen import generate_config
from omada_wg.models import WireGuardPeer, WireGuardServer


class ConfigGenerationTests(unittest.TestCase):
    def setUp(self):
        self.peer = WireGuardPeer("p1", "host", "10.0.8.2", "pub", "private", allowed_addresses=("192.168.1.1/24",))
        self.server = WireGuardServer("s1", "test", "server-pub", 51820, 25, (self.peer,))

    def test_matches_observed_shape_and_normalizes_network(self):
        rendered = generate_config(self.server, self.peer, endpoint_host="198.51.100.1", dns="192.168.1.5")
        self.assertEqual(rendered, """[Interface]
PrivateKey = private
Address = 10.0.8.2/32
DNS = 192.168.1.5

[Peer]
PublicKey = server-pub
AllowedIPs = 192.168.1.0/24
Endpoint = 198.51.100.1:51820
PersistentKeepalive = 25
""")

    def test_full_tunnel(self):
        rendered = generate_config(self.server, self.peer, endpoint_host="vpn.example", dns=None, route_mode="full")
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", rendered)

    def test_site_routes_fall_back_to_freshly_discovered_networks(self):
        peer = WireGuardPeer("p2", "new-host", "10.0.8.3", "pub", "private")
        rendered = generate_config(
            self.server, peer, endpoint_host="vpn.example", dns=None,
            route_mode="site", site_routes=("192.168.5.1/24",))
        self.assertIn("AllowedIPs = 192.168.5.0/24", rendered)

    def test_custom_individual_ip_becomes_host_route(self):
        rendered = generate_config(self.server, self.peer, endpoint_host="vpn.example", dns=None,
                                   route_mode="custom", custom_routes=("192.168.1.50", "10.20.30.0/24"))
        self.assertIn("AllowedIPs = 192.168.1.50/32, 10.20.30.0/24", rendered)


if __name__ == "__main__":
    unittest.main()
