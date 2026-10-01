import tempfile
import unittest
from pathlib import Path

from omada_wg.drive_mapping import DriveMapping, DriveMappingManager, parse_drive_maps
from omada_wg.errors import ConfigurationError


class FakeDriveProvider:
    def __init__(self, current=None, saved=None):
        self.drives = dict(current or {})
        self.saved = dict(saved or {})
        self.actions = []

    def current(self, letter):
        return self.drives.get(letter)

    def saved_details(self, letter):
        return self.saved.get(letter, (False, None, None))

    def remove(self, letter, *, persistent):
        self.actions.append(("remove", letter, persistent))
        self.drives.pop(letter, None)
        if persistent:
            self.saved.pop(letter, None)

    def add(self, mapping, *, persistent=False, username=None):
        self.actions.append(("add", mapping.letter, mapping.path, persistent, username))
        self.drives[mapping.letter] = mapping.path
        if persistent:
            self.saved[mapping.letter] = (True, username)


class DriveMappingTests(unittest.TestCase):
    def test_parser_accepts_multiple_fqdn_unc_maps(self):
        maps = parse_drive_maps(
            r"Z:=\\nas.example.com\Shared; s: = \\nas.example.com\Scans")
        self.assertEqual(maps, [
            DriveMapping("Z:", r"\\nas.example.com\Shared"),
            DriveMapping("S:", r"\\nas.example.com\Scans"),
        ])

    def test_parser_rejects_duplicate_letters(self):
        with self.assertRaisesRegex(ConfigurationError, "more than once"):
            parse_drive_maps(r"Z:=\\nas.example.com\One; Z:=\\nas.example.com\Two")

    def test_connect_replaces_short_name_and_disconnect_restores_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            provider = FakeDriveProvider(
                {"Z:": r"\\NAS\Shared"},
                {"Z:": (True, "DOMAIN\\ben", r"\\NAS\Shared")})
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")], state, provider)

            manager.connect()
            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")
            self.assertTrue(state.is_file())
            self.assertEqual(provider.actions[:2], [
                ("remove", "Z:", True),
                ("add", "Z:", r"\\nas.example.com\Shared", False, None),
            ])

            manager.disconnect()
            self.assertEqual(provider.drives["Z:"], r"\\NAS\Shared")
            self.assertEqual(provider.actions[-2:], [
                ("remove", "Z:", True),
                ("add", "Z:", r"\\NAS\Shared", True, "DOMAIN\\ben"),
            ])
            self.assertFalse(state.exists())

    def test_unused_letter_is_removed_on_disconnect(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            provider = FakeDriveProvider()
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")], state, provider)
            manager.connect()
            manager.disconnect()
            self.assertNotIn("Z:", provider.drives)

    def test_existing_target_is_left_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            provider = FakeDriveProvider({"Z:": r"\\nas.example.com\Shared"})
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")],
                Path(temporary) / "maps.json", provider)
            manager.connect()
            manager.disconnect()
            self.assertEqual(provider.actions, [])
            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")

    def test_disconnected_persistent_short_name_is_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            provider = FakeDriveProvider(
                saved={"Z:": (True, "DOMAIN\\ben", r"\\NAS\Shared")})
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")],
                Path(temporary) / "maps.json", provider)
            manager.connect()
            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")
            manager.disconnect()
            self.assertEqual(provider.drives["Z:"], r"\\NAS\Shared")


if __name__ == "__main__":
    unittest.main()
