import unittest

from omada_wg.setup_browser import CapturedSession, DiscoveryClient, _routes
from omada_wg.setup_gui import SetupWizard


class Request:
    url = "https://example/omadac/device123/omada456/api/v2/current/user-detail"
    headers = {"csrf-token": "csrf", "user-id": "user"}


class SetupDiscoveryTests(unittest.TestCase):
    def test_generated_executable_name_includes_sanitized_site(self):
        result = SetupWizard.output_for_site("Omada-WireGuard-Deployment-0.2.0.exe", "Main / Office")
        self.assertEqual(result.name, "Omada-WireGuard-Deployment-0.2.0-Main_Office.exe")

    def test_extracts_controller_and_session_metadata(self):
        captured = CapturedSession()
        captured.observe(Request())
        self.assertEqual((captured.device_id, captured.omada_id), ("device123", "omada456"))
        self.assertTrue(captured.event.is_set())

    def test_unwraps_common_list_shape(self):
        self.assertEqual(DiscoveryClient.items({"data": [{"id": "x"}]}), [{"id": "x"}])

    def test_custom_routes_normalize_hosts_and_networks(self):
        self.assertEqual(_routes("custom", "192.0.2.10, 10.2.3.4/24"),
                         ["192.0.2.10/32", "10.2.3.0/24"])


if __name__ == "__main__":
    unittest.main()
