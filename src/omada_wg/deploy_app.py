from __future__ import annotations

import ctypes
import os
import re
import shutil
import sys
import threading
from pathlib import Path

from .api import OmadaClient
from .backend import WindowsWireGuardBackend
from .bootstrap import resolve_runtime
from .cloud_discovery import CloudDiscoveryClient
from .credentials import PortableCredentialStore
from .enrollment import EnrollmentService
from .errors import EnrollmentError
from .settings import DeploymentConfig
from .state import StateStore


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        executable_dir = Path(sys.executable).resolve().parent
        if (executable_dir / "deployment.json").is_file():
            return executable_dir
        bundled = getattr(sys, "_MEIPASS", None)
        if bundled and (Path(bundled) / "deployment.json").is_file():
            return Path(bundled)
        return executable_dir
    return Path.cwd()


def _icon_path() -> Path | None:
    roots = [Path(getattr(sys, "_MEIPASS", "")), Path(__file__).resolve().parents[2]]
    for root in roots:
        candidate = root / "assets" / "omada-vpn-icon.png"
        if candidate.is_file():
            return candidate
    return None


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _elevate() -> bool:
    executable = sys.executable
    if getattr(sys, "frozen", False):
        parameters = " ".join(f'"{arg}"' for arg in sys.argv[1:])
    else:
        parameters = " ".join([f'"{Path(__file__).resolve()}"', *(f'"{arg}"' for arg in sys.argv[1:])])
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, str(_base_dir()), 1) > 32


def _enroll(config_path: Path):
    config, service = _runtime_service(config_path)
    return service.enroll()


def _runtime_service(config_path: Path) -> tuple[DeploymentConfig, EnrollmentService]:
    config = DeploymentConfig.load(config_path)
    if not config.write_enabled:
        raise EnrollmentError("This deployment package is not enabled to create an Omada client")
    if not config.credentials_file or not config.credential_key:
        raise EnrollmentError("The deployment package has no Omada cloud credentials")
    key = PortableCredentialStore.decode_key(config.credential_key)
    credentials = PortableCredentialStore(config.credentials_file, key).load()
    discovery = CloudDiscoveryClient(credentials)
    config = resolve_runtime(config, discovery)
    session = discovery.session
    api = OmadaClient(config, session)
    display_name = f"Company: {config.site_name} VPN" if config.site_name else "Company VPN"
    backend = WindowsWireGuardBackend(
        installer_dir=config.wireguard_msi_dir,
        controller_executable=_installed_executable(config.site_name),
        display_name=display_name)
    return config, EnrollmentService(config, api, backend, StateStore(config.state_path))


def _unenroll(config_path: Path) -> bool:
    _, service = _runtime_service(config_path)
    return service.unenroll()


def _install_location() -> Path:
    return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Omada WireGuard Deployment"


def _installed_executable(site_name: str | None = None) -> Path:
    safe_site = re.sub(r"[^A-Za-z0-9]+", "-", site_name or "Company").strip("-")
    return _install_location() / f"{safe_site or 'Company'}-VPN-Tray.exe"


def _close_existing_tray() -> None:
    try:
        import win32con
        import win32gui
        tray = win32gui.FindWindow("OmadaCompanyVpnTrayWindow", None)
        if tray:
            win32gui.PostMessage(tray, win32con.WM_CLOSE, 0, 0)
    except Exception:
        pass


def _register_uninstaller(config_path: Path) -> None:
    import winreg

    destination = _install_location()
    destination.mkdir(parents=True, exist_ok=True)
    installed_config = destination / "deployment.json"
    source_config = DeploymentConfig.load(config_path)
    executable = _installed_executable(source_config.site_name)
    if not source_config.credentials_file:
        raise EnrollmentError("Deployment credential vault is missing")
    credentials = destination / "deployment.credentials.bin"
    if Path(sys.executable).resolve() != executable.resolve():
        shutil.copy2(sys.executable, executable)
    if not executable.is_file() or executable.stat().st_size == 0:
        raise EnrollmentError("The Company VPN tray executable was not installed")
    shutil.copy2(config_path, installed_config)
    shutil.copy2(source_config.credentials_file, credentials)
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OmadaWireGuardDeployment"
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE) as key:
        display_name = (f"Company: {source_config.site_name} VPN (Omada WireGuard)"
                        if source_config.site_name else "Company VPN (Omada WireGuard)")
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, display_name)
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "0.1.0")
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "Company IT")
        winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, str(executable))
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(destination))
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, f'"{executable}" --uninstall')
        winreg.SetValueEx(key, "QuietUninstallString", 0, winreg.REG_SZ,
                          f'"{executable}" --uninstall --quiet')
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)


def _remove_registration_and_files(config_path: Path) -> None:
    import winreg

    _close_existing_tray()

    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OmadaWireGuardDeployment"
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
    except FileNotFoundError:
        pass
    install_dir = _install_location().resolve()
    if config_path.resolve().parent != install_dir:
        return
    config = DeploymentConfig.load(config_path)
    for path in (config.credentials_file, config_path):
        if path:
            try:
                Path(path).unlink()
            except FileNotFoundError:
                pass
    move_file_ex = ctypes.windll.kernel32.MoveFileExW
    delay_until_reboot = 0x4
    move_file_ex(str(_installed_executable(config.site_name)), None, delay_until_reboot)
    move_file_ex(str(install_dir), None, delay_until_reboot)


def main() -> int:
    if sys.platform != "win32":
        print("This deployment app currently supports Windows only.", file=sys.stderr)
        return 2
    if "--tray" in sys.argv[1:]:
        from .tray import run_tray
        try:
            config = DeploymentConfig.load(_base_dir() / "deployment.json")
            display_name = f"Company: {config.site_name} VPN" if config.site_name else "Company VPN"
            return run_tray(
                config.tunnel_name, display_name, drive_maps=config.drive_maps,
                disconnect_on_office_dns=config.disconnect_on_office_dns)
        except Exception:
            return 2
    uninstall = "--uninstall" in sys.argv[1:]
    quiet = "--quiet" in sys.argv[1:]
    config_path = _base_dir() / "deployment.json"
    if not _is_admin():
        return 0 if _elevate() else 2
    _close_existing_tray()

    if quiet:
        try:
            if uninstall:
                _unenroll(config_path)
                _remove_registration_and_files(config_path)
            else:
                _enroll(config_path)
                _register_uninstaller(config_path)
            return 0
        except Exception:
            return 2

    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("Remove Company VPN" if uninstall else "Company VPN")
    root.geometry("560x330")
    root.resizable(False, False)
    icon = _icon_path()
    if icon:
        root._app_icon = tk.PhotoImage(file=str(icon))
        root.iconphoto(True, root._app_icon)
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    style.configure("Title.TLabel", font=("Segoe UI", 17, "bold"))
    style.configure("Subtitle.TLabel", font=("Segoe UI", 10), foreground="#52606d")
    frame = ttk.Frame(root, padding=28)
    frame.pack(fill="both", expand=True)
    heading = "Removing Company VPN" if uninstall else "Connecting this PC to Company VPN"
    ttk.Label(frame, text=heading, style="Title.TLabel").pack(pady=(4, 5))
    subtitle = ("The tunnel and its Omada enrollment will be removed."
                if uninstall else "Securely contacting your organization’s Omada controller.")
    ttk.Label(frame, text=subtitle, style="Subtitle.TLabel").pack(pady=(0, 14))
    status = tk.StringVar(value="Connecting to Omada Cloud…")
    ttk.Label(frame, textvariable=status, font=("Segoe UI", 11)).pack(pady=8)
    progress = ttk.Progressbar(frame, mode="indeterminate", length=390)
    progress.pack(pady=16)
    progress.start(12)
    boot_enabled = tk.BooleanVar(value=True)
    boot_option = ttk.Checkbutton(
        frame, text="Start Company VPN automatically with Windows", variable=boot_enabled)
    finish_button = ttk.Button(frame, text="Finish")
    working = True
    exit_code = 0

    def close_window() -> None:
        if working:
            messagebox.showwarning(
                "VPN operation in progress",
                "Please wait for the current VPN operation to finish so it can complete or roll back safely.",
                parent=root,
            )
            return
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close_window)

    def work() -> None:
        try:
            if uninstall:
                removed = _unenroll(config_path)
                _remove_registration_and_files(config_path)
                result = None
            else:
                result = _enroll(config_path)
                _register_uninstaller(config_path)
        except Exception as exc:
            root.after(0, lambda detail=str(exc): failed(detail))
        else:
            root.after(0, lambda: succeeded(None if uninstall else result.client_name))

    def failed(detail: str) -> None:
        nonlocal working, exit_code
        working = False
        exit_code = 2
        progress.stop()
        status.set("Setup could not be completed.")
        messagebox.showerror("VPN setup", detail, parent=root)

    def succeeded(client_name: str | None) -> None:
        nonlocal working
        working = False
        progress.stop()
        if uninstall:
            status.set("VPN removed and computer unenrolled.")
            messagebox.showinfo("VPN removed", "The WireGuard tunnel and Omada client were removed.", parent=root)
            root.destroy()
        else:
            status.set(f"Connected as {client_name}")
            boot_option.pack(pady=(10, 5))
            finish_button.configure(command=finish_install)
            finish_button.pack(pady=(8, 0))

    def finish_install() -> None:
        try:
            config = DeploymentConfig.load(config_path)
            display_name = f"Company: {config.site_name} VPN" if config.site_name else "Company VPN"
            WindowsWireGuardBackend(
                controller_executable=_installed_executable(config.site_name),
                display_name=display_name).configure_access(
                config.tunnel_name,
                desktop_shortcut=True,
                launch_manager=True,
                start_with_windows=boot_enabled.get(),
            )
        except Exception as exc:
            messagebox.showerror("Cannot save startup preference", str(exc), parent=root)
            return
        root.destroy()

    threading.Thread(target=work, daemon=False).start()
    root.mainloop()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
