import base64
import unittest

from omada_wg.keys import _x25519, generate_keypair


class KeyTests(unittest.TestCase):
    def test_rfc7748_vector(self):
        scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        self.assertEqual(_x25519(scalar, u).hex(), expected)

    def test_generated_wireguard_keys_are_32_bytes(self):
        private, public = generate_keypair()
        self.assertEqual(len(base64.b64decode(private)), 32)
        self.assertEqual(len(base64.b64decode(public)), 32)

