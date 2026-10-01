import tempfile
import unittest
from pathlib import Path

from omada_wg.credentials import CloudCredentials, CredentialStore, PortableCredentialStore


class CredentialStoreTests(unittest.TestCase):
    def test_dpapi_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.dpapi"
            store = CredentialStore(path)
            expected = CloudCredentials("admin@example.test", "correct horse battery staple")
            store.save(expected)
            self.assertEqual(store.load(), expected)

    def test_portable_vault_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            key = PortableCredentialStore.generate_key()
            store = PortableCredentialStore(Path(directory) / "credentials.bin", key)
            expected = CloudCredentials("admin@example.com", "password")
            store.save(expected)
            self.assertEqual(store.load(), expected)
            self.assertEqual(PortableCredentialStore.decode_key(PortableCredentialStore.encode_key(key)), key)


if __name__ == "__main__":
    unittest.main()
