import unittest

from omada_wg.deploy_app import _installed_executable


class DeployAppTests(unittest.TestCase):
    def test_installed_tray_name_includes_site(self):
        self.assertEqual(
            _installed_executable("DRK Law Office").name,
            "DRK-Law-Office-VPN-Tray.exe",
        )

    def test_installed_tray_name_removes_windows_unsafe_characters(self):
        self.assertEqual(
            _installed_executable("Main / Office: East").name,
            "Main-Office-East-VPN-Tray.exe",
        )


if __name__ == "__main__":
    unittest.main()
