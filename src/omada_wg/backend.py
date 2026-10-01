from __future__ import annotations

import os
import platform
import re
import ipaddress
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path

from .errors import BackendError


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
        wg = str(Path(self.executable).with_name("wg.exe"))
        deadline = time.monotonic() + timeout
        last_detail = ""
        while time.monotonic() < deadline:
            service = self._run(["sc.exe", "query", self._service(tunnel_name)], ok=(0, 1060))
            if service.returncode == 0 and "RUNNING" in service.stdout:
                status = self._run([wg, "show", tunnel_name, "latest-handshakes"], ok=(0, 1))
                last_detail = (status.stderr or status.stdout).strip()
                for line in status.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[-1].isdigit() and int(parts[-1]) > 0:
                        return
            time.sleep(1)
        raise BackendError("WireGuard tunnel started but did not complete a handshake" +
                           (f": {last_detail}" if last_detail else ""))

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
