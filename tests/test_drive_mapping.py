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


class DelayedReleaseDriveProvider(FakeDriveProvider):
    """Simulates Windows briefly retaining a letter after an unmap request."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_release: dict[str, int] = {}

    def remove(self, letter, *, persistent):
        super().remove(letter, persistent=persistent)
        self.pending_release[letter] = 2

    def current(self, letter):
        pending = self.pending_release.get(letter, 0)
        if pending:
            self.pending_release[letter] = pending - 1
            return r"\\Windows-is-still-releasing\Share"
        return super().current(letter)


class RecentPolicyDriveProvider(FakeDriveProvider):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.policy_ages = [0.0, 0.0, None]
        self.policy_checks = 0

    def profile_age_seconds(self, letter):
        self.policy_checks += 1
        return self.policy_ages.pop(0) if self.policy_ages else None


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
                ("remove", "Z:", False),
                ("add", "Z:", r"\\nas.example.com\Shared", False, None),
            ])

            manager.disconnect()
            self.assertEqual(provider.drives["Z:"], r"\\NAS\Shared")
            self.assertEqual(provider.actions[-2:], [
                ("remove", "Z:", False),
                ("add", "Z:", r"\\NAS\Shared", True, "DOMAIN\\ben"),
            ])
            self.assertFalse(state.exists())

    def test_connect_waits_for_windows_to_release_letter_before_remapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            provider = DelayedReleaseDriveProvider({"Z:": r"\\NAS\Shared"})
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")],
                Path(temporary) / "maps.json", provider, release_poll_interval=0)

            manager.connect()

            self.assertEqual(provider.pending_release["Z:"], 0)
            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")

    def test_connect_waits_for_a_recent_group_policy_drive_update_to_settle(self):
        with tempfile.TemporaryDirectory() as temporary:
            provider = RecentPolicyDriveProvider({"Z:": r"\\NAS\Shared"})
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")],
                Path(temporary) / "maps.json", provider, policy_poll_interval=0)

            manager.connect()

            self.assertEqual(provider.policy_checks, 3)
            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")

    def test_unused_letter_is_left_untouched_on_disconnect(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            provider = FakeDriveProvider()
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")], state, provider)
            manager.connect()
            manager.disconnect()
            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")

    def test_no_configured_mappings_do_not_read_stale_state_on_disconnect(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            state.write_text("not valid json", encoding="utf-8")
            provider = FakeDriveProvider()
            manager = DriveMappingManager([], state, provider)

            manager.disconnect()

            self.assertEqual(provider.actions, [])

    def test_blank_restore_path_leaves_new_mapping_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            provider = FakeDriveProvider()
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")], state, provider)

            manager.connect()
            manager.disconnect()

            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")
            self.assertFalse(state.exists())

    def test_reconnect_recreates_a_vpn_mapping_removed_mid_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            provider = FakeDriveProvider()
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")], state, provider)

            manager.connect()
            provider.drives.pop("Z:")  # Simulate a manual removal while connected.

            manager.connect()

            self.assertEqual(provider.drives["Z:"], r"\\nas.example.com\Shared")
            self.assertEqual(provider.actions[-1],
                             ("add", "Z:", r"\\nas.example.com\Shared", False, None))

    def test_disconnect_does_not_restore_a_mapping_removed_manually(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            provider = FakeDriveProvider(
                {"Z:": r"\\NAS\Shared"},
                {"Z:": (True, None, r"\\NAS\Shared")})
            manager = DriveMappingManager(
                [DriveMapping("Z:", r"\\nas.example.com\Shared")], state, provider)

            manager.connect()
            provider.drives.pop("Z:")  # The user removes the VPN drive.
            manager.disconnect()

            self.assertEqual(provider.actions, [
                ("remove", "Z:", False),
                ("add", "Z:", r"\\nas.example.com\Shared", False, None),
            ])
            self.assertFalse(state.exists())

    def test_explicit_lan_restore_path_is_used_without_a_previous_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "maps.json"
            provider = FakeDriveProvider()
            manager = DriveMappingManager(
                [DriveMapping(
                    "S:", r"\\nas.dimlaw.local\shared\Scans",
                    r"\\DRK-NAS9B372E\shared\Scans")], state, provider)
            manager.connect()
            manager.disconnect()
            self.assertEqual(provider.drives["S:"], r"\\DRK-NAS9B372E\shared\Scans")

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
