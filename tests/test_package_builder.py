import unittest

from omada_wg.package_builder import _latest_msi


class PackageBuilderTests(unittest.TestCase):
    def test_selects_latest_architecture_specific_msi(self):
        index = 'wireguard-amd64-1.0.2.msi wireguard-arm64-9.0.msi wireguard-amd64-1.1.msi'
        self.assertEqual(_latest_msi(index, "amd64"), "wireguard-amd64-1.1.msi")


if __name__ == "__main__":
    unittest.main()
