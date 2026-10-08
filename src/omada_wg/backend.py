from __future__ import annotations

import os
import platform
import re
import ipaddress
import shutil
import socket
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from .errors import BackendError


@dataclass(frozen=True)
class ConnectionDiagnostic:
    """A user-facing explanation for a WireGuard connection that has no handshake."""
    code: str
    message: str

    def peer_removed(self) -> "ConnectionDiagnostic":
        return ConnectionDiagnostic(
            "peer_removed",
            "This PC's VPN peer is no longer registered with Omada. Use Repair / re-enroll to create a new peer.",
        )


class WireGuardBackend(ABC):
    @abstractmethod
    def install_and_start(self, tunnel_name: str, config: str) -> None: ...

    @abstractmethod
    def status(self, tunnel_name: str) -> str: ...

    @abstractmethod
    def start(self, tunnel_name: str) -> None: ...

    @abstractmethod
    def stop(self, tunnel_name: str) -> None: ...

    @abstractmethod
    def remove(self, tunnel_name: str) -> None: ...

    @abstractmethod
    def configure_access(self, tunnel_name: str, *, desktop_shortcut: bool,
                         launch_manager: bool, start_with_windows: bool) -> None: ...


class WindowsWireGuardBackend(WireGuardBackend):
    def __init__(self, executable: str | None = None, installer_dir: str | Path | None = None,
                 controller_executable: str | Path | None = None,
                 display_name: str = "Company VPN"):
        default = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WireGuard" / "wireguard.exe"
        self.executable = executable or shutil.which("wireguard.exe") or str(default)
        self.installer_dir = Path(installer_dir) if installer_dir else None
        self.config_dir = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "OmadaWireGuard"
        self.controller_executable = Path(controller_executable) if controller_executable else (
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) /
            "Omada WireGuard Deployment" / "Company-VPN-Tray.exe")
        self.display_name = display_name

    def _shortcut_name(self) -> str:
        safe = re.sub(r'[<>:"/\\|?*]+', "_", self.display_name).strip(" .")
        return (safe or "Company VPN") + ".lnk"

    @staticmethod
    def _service(tunnel_name: str) -> str:
        if not tunnel_name or any(c in tunnel_name for c in '\\/"'):
            raise BackendError("Invalid tunnel name")
        return f"WireGuardTunnel${tunnel_name}"

    def _run(self, args: list[str], *, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            result = subprocess.run(
                args, text=True, capture_output=True, check=False,
                creationflags=creationflags)
        except OSError as exc:
            raise BackendError(f"Cannot run WireGuard: {exc}") from exc
        if result.returncode not in ok:
            detail = (result.stderr or result.stdout).strip()
            raise BackendError(f"WireGuard command failed ({result.returncode}): {detail}")
        return result

    @staticmethod
    def _architecture() -> str:
        machine = platform.machine().casefold()
        if machine in {"amd64", "x86_64"}:
            return "amd64"
        if machine in {"arm64", "aarch64"}:
            return "arm64"
        if machine in {"x86", "i386", "i686"}:
            return "x86"
        raise BackendError(f"Unsupported Windows architecture: {platform.machine()}")

    def ensure_installed(self) -> None:
        if Path(self.executable).is_file():
            return
        if not self.installer_dir:
            raise BackendError("WireGuard is not installed and no bundled installer directory was configured")
        candidates = sorted(self.installer_dir.glob(f"wireguard-{self._architecture()}-*.msi"))
        if len(candidates) != 1:
            raise BackendError(f"Expected one bundled WireGuard MSI for {self._architecture()}, found {len(candidates)}")
        self._run([
            "msiexec.exe", "/i", str(candidates[0]), "/qn", "/norestart", "DO_NOT_LAUNCH=1",
        ])
        if not Path(self.executable).is_file():
            raise BackendError("WireGuard installation completed but wireguard.exe was not found")

    def _secure_config(self, tunnel_name: str, config: str) -> Path:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        conf = self.config_dir / f"{tunnel_name}.conf"
        temp = conf.with_suffix(".conf.tmp")
        temp.write_text(config, encoding="utf-8", newline="\n")
        os.chmod(temp, 0o600)
        result = self._run([
            "icacls.exe", str(temp), "/inheritance:r", "/grant:r",
            "*S-1-5-18:(F)", "*S-1-5-32-544:(F)", "*S-1-5-32-545:(R)",
        ])
        temp.replace(conf)
        return conf

    def _wait_for_connection(self, tunnel_name: str, timeout: float = 20) -> None:
        diagnostic = self.diagnose_connection(tunnel_name, timeout=timeout)
        if diagnostic:
            raise BackendError(diagnostic.message)

    def _handshake_completed(self, tunnel_name: str) -> bool:
        wg = str(Path(self.executable).with_name("wg.exe"))
        status = self._run([wg, "show", tunnel_name, "latest-handshakes"], ok=(0, 1))
        return any(
            len(parts := line.split()) >= 2 and parts[-1].isdigit() and int(parts[-1]) > 0
            for line in status.stdout.splitlines())

    def _configured_endpoint(self, tunnel_name: str) -> tuple[str, int] | None:
        """Read the endpoint from the local managed config without exposing its secrets."""
        try:
            contents = (self.config_dir / f"{tunnel_name}.conf").read_text(encoding="utf-8")
        except OSError:
            return None
        match = re.search(r"(?mi)^Endpoint\s*=\s*(.+?)\s*$", contents)
        if not match:
            return None
        endpoint = match.group(1).strip()
        if endpoint.startswith("["):
            closing = endpoint.find("]")
            if closing > 1 and endpoint[closing + 1:].startswith(":"):
                host, port = endpoint[1:closing], endpoint[closing + 2:]
            else:
                return None
        else:
            host, separator, port = endpoint.rpartition(":")
            if not separator:
                return None
        try:
            return host, int(port)
        except ValueError:
            return None

    @staticmethod
    def _internet_available() -> bool:
        """Confirm a usable route to the public Internet without changing local state."""
        try:
            with socket.create_connection(("1.1.1.1", 443), timeout=3):
                return True
        except OSError:
            return False

    def diagnose_connection(self, tunnel_name: str, *, timeout: float = 15) -> ConnectionDiagnostic | None:
        """Wait for a handshake, then distinguish offline clients from endpoint failures.

        A WireGuard endpoint intentionally gives no protocol response for an unknown
        peer.  The caller may pair the endpoint result with a controller-side peer
        check to identify an explicitly deleted peer.
        """
        deadline = time.monotonic() + timeout
        service_was_running = False
        while True:
            service = self._run(["sc.exe", "query", self._service(tunnel_name)], ok=(0, 1060))
            if service.returncode == 0 and "RUNNING" in service.stdout:
                service_was_running = True
                if self._handshake_completed(tunnel_name):
                    return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(1, remaining))
        if not service_was_running:
            return ConnectionDiagnostic(
                "service_not_running",
                "The local WireGuard tunnel service did not stay running. Reconnect or use Repair / re-enroll.",
            )
        if not self._internet_available():
            return ConnectionDiagnostic(
                "no_internet",
                "This PC could not reach the public internet. Connect to the internet, then retry the VPN.",
            )
        endpoint = self._configured_endpoint(tunnel_name)
        if endpoint:
            host, port = endpoint
            try:
                socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
            except socket.gaierror:
                return ConnectionDiagnostic(
                    "endpoint_unreachable",
                    f"The configured VPN gateway {host} could not be resolved. Check the public gateway or DDNS name.",
                )
            endpoint_label = f"{host}:{port}"
        else:
            endpoint_label = "the configured VPN gateway"
        return ConnectionDiagnostic(
            "endpoint_unreachable",
            f"The VPN gateway ({endpoint_label}) did not respond to a WireGuard handshake. "
            "It may be unreachable or its UDP port may be blocked.",
        )

    def _remove_conflicting_tunnel_services(self, tunnel_name: str, config: str) -> None:
        match = re.search(r"(?mi)^Address\s*=\s*([^,\s/]+)", config)
        if not match:
            return
        try:
            address = str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            return
        powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / \
            "WindowsPowerShell" / "v1.0" / "powershell.exe"
        script = (
            "& { param([string]$Ip) @(Get-NetIPAddress -IPAddress $Ip "
            "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias) -join \"`n\" }")
        result = self._run([
            str(powershell), "-NoProfile", "-NonInteractive", "-Command", script, address])
        aliases = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        for alias in aliases:
            if alias.casefold() == tunnel_name.casefold():
                continue
            service = self._run(["sc.exe", "query", self._service(alias)], ok=(0, 1060))
            if service.returncode == 0:
                self._run([self.executable, "/uninstalltunnelservice", alias])

    def launch_controller(self) -> None:
        shortcut = self._shortcut_path("Desktop")
        try:
            subprocess.Popen(
                ["explorer.exe", str(shortcut)], close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError as exc:
            raise BackendError(f"Cannot launch the Company VPN tray controller: {exc}") from exc

    def _shortcut_path(self, location: str) -> Path:
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            return Path(shell.SpecialFolders(location)) / self._shortcut_name()
        except Exception as exc:
            raise BackendError(f"Cannot locate the {location} shortcut folder: {exc}") from exc

    def _controller_shortcut(self, location: str, enabled: bool) -> None:
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            path = self._shortcut_path(location)
            if not enabled:
                candidates = {path, Path(shell.SpecialFolders(location)) / "Company VPN.lnk"}
                for candidate in candidates:
                    try:
                        candidate.unlink()
                    except FileNotFoundError:
                        pass
                return
            shortcut = shell.CreateShortcut(str(path))
            shortcut.TargetPath = str(self.controller_executable)
            shortcut.Arguments = "--tray"
            shortcut.WorkingDirectory = str(self.controller_executable.parent)
            shortcut.Description = f"Open {self.display_name} connection controls"
            shortcut.IconLocation = f"{self.controller_executable},0"
            shortcut.Save()
        except Exception as exc:
            raise BackendError(f"Cannot update the {location} WireGuard shortcut: {exc}") from exc

    def _controller_autostart(self, enabled: bool) -> None:
        """Register the tray at logon without relying on a fragile Startup shortcut."""
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            value_name = "OmadaWireGuardTray"
            with winreg.CreateKeyEx(
                    winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                    winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                if enabled:
                    command = f'"{self.controller_executable}" --tray'
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, command)
                    saved, _ = winreg.QueryValueEx(key, value_name)
                    if saved != command:
                        raise BackendError("Windows did not retain the tray startup registration")
                else:
                    try:
                        winreg.DeleteValue(key, value_name)
                    except FileNotFoundError:
                        pass
        except BackendError:
            raise
        except Exception as exc:
            raise BackendError(f"Cannot update the WireGuard tray startup registration: {exc}") from exc

    def _controller_service_trigger(self, tunnel_name: str, enabled: bool) -> None:
        """Launch the per-user tray after this tunnel service enters RUNNING."""
        task_name = f"Omada WireGuard Tray - {tunnel_name}"
        if not enabled:
            self._run(["schtasks.exe", "/delete", "/tn", task_name, "/f"], ok=(0, 1))
            return
        user = os.environ.get("USERDOMAIN", "")
        username = os.environ.get("USERNAME", "")
        account = f"{user}\\{username}" if user and username else username
        if not account:
            raise BackendError("Cannot determine the signed-in user for the tray trigger")
        event_query = (
            "*[System[Provider[@Name='Service Control Manager'] and EventID=7036] "
            f"and EventData[Data='{self._service(tunnel_name)}'] and EventData[Data='running']]")
        self._run([
            "schtasks.exe", "/create", "/tn", task_name,
            "/tr", f'"{self.controller_executable}" --tray',
            "/sc", "onevent", "/ec", "System", "/mo", event_query,
            "/ru", account, "/it", "/rl", "LIMITED", "/f",
        ])

    def _grant_interactive_service_controls(self, tunnel_name: str) -> None:
        service = self._service(tunnel_name)
        result = self._run(["sc.exe", "sdshow", service])
        sddl = next((line.strip() for line in result.stdout.splitlines()
                     if line.strip().startswith("D:")), "")
        if not sddl:
            raise BackendError("Windows did not return the tunnel service permissions")
        if re.search(r"\(A;;[^)]*RP[^)]*WP[^)]*;;;IU\)", sddl):
            return
        marker = sddl.find("S:")
        ace = "(A;;RPWP;;;IU)"
        updated = sddl + ace if marker < 0 else sddl[:marker] + ace + sddl[marker:]
        self._run(["sc.exe", "sdset", service, updated])
        verified = self._run(["sc.exe", "sdshow", service])
        verified_sddl = next((line.strip() for line in verified.stdout.splitlines()
                              if line.strip().startswith("D:")), "")
        if not re.search(r"\(A;;[^)]*RP[^)]*WP[^)]*;;;IU\)", verified_sddl):
            raise BackendError("Windows did not retain the tray start/stop service permissions")

    def configure_access(self, tunnel_name: str, *, desktop_shortcut: bool,
                         launch_manager: bool, start_with_windows: bool) -> None:
        self._run([
            "sc.exe", "config", self._service(tunnel_name), "start=",
            "auto" if start_with_windows else "demand",
        ])
        self._grant_interactive_service_controls(tunnel_name)
        self._controller_shortcut("Desktop", desktop_shortcut)
        # Remove shortcuts produced by older builds and use the machine Run key.
        self._controller_shortcut("Startup", False)
        self._controller_autostart(start_with_windows)
        self._controller_service_trigger(tunnel_name, True)
        if launch_manager:
            self.launch_controller()

    def install_and_start(self, tunnel_name: str, config: str) -> None:
        service = self._service(tunnel_name)
        self.ensure_installed()
        self._remove_conflicting_tunnel_services(tunnel_name, config)
        existing = self._run(["sc.exe", "query", service], ok=(0, 1060))
        if existing.returncode == 0:
            self._run([self.executable, "/uninstalltunnelservice", tunnel_name])
        conf = self._secure_config(tunnel_name, config)
        self._run([self.executable, "/installtunnelservice", str(conf)])
        current = self._run(["sc.exe", "query", service], ok=(0, 1060))
        if current.returncode or "RUNNING" not in current.stdout:
            self._run(["sc.exe", "start", service], ok=(0, 1056))
        self._wait_for_connection(tunnel_name)

    def status(self, tunnel_name: str) -> str:
        result = self._run(["sc.exe", "query", self._service(tunnel_name)], ok=(0, 1060))
        if result.returncode == 1060:
            return "unavailable"
        if "RUNNING" in result.stdout:
            return "running"
        if "START_PENDING" in result.stdout:
            return "starting"
        if "STOP_PENDING" in result.stdout:
            return "stopping"
        return "stopped"

    def start(self, tunnel_name: str) -> None:
        self._run(["sc.exe", "start", self._service(tunnel_name)], ok=(0, 1056))

    def stop(self, tunnel_name: str) -> None:
        self._run(["sc.exe", "stop", self._service(tunnel_name)], ok=(0, 1062))

    def remove(self, tunnel_name: str) -> None:
        existing = self._run(["sc.exe", "query", self._service(tunnel_name)], ok=(0, 1060))
        if existing.returncode != 1060:
            self.ensure_installed()
            self._run([self.executable, "/uninstalltunnelservice", tunnel_name])
        try:
            (self.config_dir / f"{tunnel_name}.conf").unlink()
        except FileNotFoundError:
            pass
        self._controller_shortcut("Desktop", False)
        self._controller_shortcut("Startup", False)
        self._controller_autostart(False)
        self._controller_service_trigger(tunnel_name, False)
