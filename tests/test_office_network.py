import unittest

from omada_wg.drive_mapping import DriveMapping
from omada_wg.office_network import OfficeDnsDetector, normalize_dns_suffix, office_dns_suffixes


class FakeDnsProvider:
    def __init__(self, suffixes):
        self.suffixes = set(suffixes)
        self.seen_tunnel = None

    def suffixes_except(self, tunnel_name):
        self.seen_tunnel = tunnel_name
        return self.suffixes


class OfficeDnsDetectorTests(unittest.TestCase):
    def test_derives_domain_from_fqdn_unc_share(self):
        suffixes = office_dns_suffixes([
            DriveMapping("Z:", r"\\nas.drklawoffice.local\Shared"),
            DriveMapping("S:", r"\\nas.drklawoffice.local\Scans"),
        ])
        self.assertEqual(suffixes, {"drklawoffice.local"})

    def test_detects_matching_non_wireguard_suffix(self):
        provider = FakeDnsProvider({"drklawoffice.local"})
        detector = OfficeDnsDetector(
            [DriveMapping("Z:", r"\\nas.drklawoffice.local\Shared")],
            enabled=True, provider=provider)
        self.assertTrue(detector.is_on_office_network("DRKNET"))
        self.assertEqual(provider.seen_tunnel, "DRKNET")

    def test_explicit_suffix_is_independent_of_drive_mappings(self):
        provider = FakeDnsProvider({"office.example.local"})
        detector = OfficeDnsDetector(
            (), enabled=True, suffix="OFFICE.example.local.", provider=provider)
        self.assertTrue(detector.is_on_office_network("DRKNET"))

    def test_explicit_suffix_does_not_use_a_different_drive_map_domain(self):
        detector = OfficeDnsDetector(
            [DriveMapping("Z:", r"\\nas.files.example\Shared")], enabled=True,
            suffix="office.example.local", provider=FakeDnsProvider({"files.example"}))
        self.assertFalse(detector.is_on_office_network("DRKNET"))

    def test_rejects_invalid_explicit_suffix(self):
        with self.assertRaises(ValueError):
            normalize_dns_suffix("not a domain")

    def test_does_not_disconnect_for_unrelated_home_suffix(self):
        detector = OfficeDnsDetector(
            [DriveMapping("Z:", r"\\nas.drklawoffice.local\Shared")],
            enabled=True, provider=FakeDnsProvider({"home"}))
        self.assertFalse(detector.is_on_office_network("DRKNET"))

    def test_disabled_detector_never_checks_the_network(self):
        provider = FakeDnsProvider({"drklawoffice.local"})
        detector = OfficeDnsDetector(
            [DriveMapping("Z:", r"\\nas.drklawoffice.local\Shared")],
            enabled=False, provider=provider)
        self.assertFalse(detector.is_on_office_network("DRKNET"))
        self.assertIsNone(provider.seen_tunnel)


if __name__ == "__main__":
    unittest.main()
