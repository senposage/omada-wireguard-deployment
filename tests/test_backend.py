import subprocess
import tempfile
import unittest
from pathlib import Path

from omada_wg.backend import WindowsWireGuardBackend


class RecordingBackend(WindowsWireGuardBackend):
    def __init__(self, root: Path):
        executable = root / "wireguard.exe"
        executable.write_bytes(b"test")
        super().__init__(executable=str(executable))
        self.config_dir = root / "config"
        self.commands = []
        self.waited = False

    def _run(self, args, *, ok=(0,)):
        self.commands.append(args)
        if args[:2] == ["sc.exe", "query"]:
            query_count = sum(1 for item in self.commands if item[:2] == ["sc.exe", "query"])
            if query_count == 1:
                return subprocess.CompletedProcess(args, 1060, "", "")
            return subprocess.CompletedProcess(args, 0, "STATE : 4 RUNNING", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def _wait_for_connection(self, tunnel_name, timeout=20):
        self.waited = True


class WindowsBackendTests(unittest.TestCase):
    def test_tunnel_service_keeps_a_persistent_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = RecordingBackend(Path(temporary))
            backend.install_and_start("omada", "[Interface]\nPrivateKey = test\n")
            config = backend.config_dir / "omada.conf"
            self.assertTrue(config.is_file())
            self.assertIn("PrivateKey = test", config.read_text(encoding="utf-8"))
            install = next(command for command in backend.commands
                           if "/installtunnelservice" in command)
            self.assertEqual(Path(install[-1]), config)
            acl = next(command for command in backend.commands if command[0] == "icacls.exe")
            self.assertIn("*S-1-5-32-545:(R)", acl)
            self.assertTrue(backend.waited)

    def test_user_can_stop_the_installed_tunnel_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = RecordingBackend(Path(temporary))
            backend.stop("omada")
            self.assertEqual(
                backend.commands[-1],
                ["sc.exe", "stop", "WireGuardTunnel$omada"],
            )

    def test_user_can_start_the_installed_tunnel_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = RecordingBackend(Path(temporary))
            backend.start("omada")
            self.assertEqual(
                backend.commands[-1],
                ["sc.exe", "start", "WireGuardTunnel$omada"],
            )

    def test_site_display_name_becomes_a_windows_safe_shortcut(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = WindowsWireGuardBackend(
                executable=str(Path(temporary) / "wireguard.exe"),
                display_name="Company: Main/Office VPN")
            self.assertEqual(backend._shortcut_name(), "Company_ Main_Office VPN.lnk")

    def test_default_installed_controller_has_an_identifiable_name(self):
        backend = WindowsWireGuardBackend()
        self.assertEqual(backend.controller_executable.name, "Company-VPN-Tray.exe")

    def test_tray_user_is_granted_start_and_stop_rights(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = RecordingBackend(Path(temporary))

            def run(args, *, ok=(0,)):
                backend.commands.append(args)
                if args[:2] == ["sc.exe", "sdshow"]:
                    granted = any(item[:2] == ["sc.exe", "sdset"] for item in backend.commands)
                    return subprocess.CompletedProcess(
                        args, 0,
                        ("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)" +
                         ("(A;;RPWP;;;IU)" if granted else "") + "\n"), "")
                return subprocess.CompletedProcess(args, 0, "", "")

            backend._run = run
            backend._grant_interactive_service_controls("omada")
            command = next(item for item in backend.commands if item[:2] == ["sc.exe", "sdset"])
            self.assertEqual(command[:3], ["sc.exe", "sdset", "WireGuardTunnel$omada"])
            self.assertIn("(A;;RPWP;;;IU)", command[3])

    def test_install_removes_only_a_tunnel_using_the_same_client_ip(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = RecordingBackend(Path(temporary))

            def run(args, *, ok=(0,)):
                backend.commands.append(args)
                if str(args[0]).casefold().endswith("powershell.exe"):
                    return subprocess.CompletedProcess(args, 0, "DRKNET\n", "")
                if args[:2] == ["sc.exe", "query"]:
                    return subprocess.CompletedProcess(args, 0, "STATE : 4 RUNNING", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            backend._run = run
            backend._remove_conflicting_tunnel_services(
                "omada", "[Interface]\nAddress = 10.0.8.3/32\n")
            self.assertIn(
                [str(backend.executable), "/uninstalltunnelservice", "DRKNET"],
                backend.commands,
            )


if __name__ == "__main__":
    unittest.main()
