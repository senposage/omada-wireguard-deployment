from __future__ import annotations

import ctypes
import os
import sys
import time
import traceback
from pathlib import Path

from .backend import WindowsWireGuardBackend
from .errors import BackendError
from .drive_mapping import DriveMapping, DriveMappingManager
from .office_network import OfficeDnsDetector


def set_tunnel_running(backend: WindowsWireGuardBackend, tunnel_name: str,
                       running: bool, *, timeout: float = 10) -> None:
    if not running:
        if backend.status(tunnel_name) in {"stopped", "unavailable"}:
            return
        backend.stop(tunnel_name)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if backend.status(tunnel_name) in {"stopped", "unavailable"}:
                return
            time.sleep(0.25)
        raise BackendError("The VPN service did not stop in time")
    if backend.status(tunnel_name) in {"running", "starting"}:
        backend.stop(tunnel_name)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if backend.status(tunnel_name) in {"stopped", "unavailable"}:
                break
            time.sleep(0.25)
        else:
            raise BackendError("The VPN service did not stop in time to reconnect")
    backend.start(tunnel_name)


def stop_tunnel_on_tray_exit(backend: WindowsWireGuardBackend, tunnel_name: str) -> None:
    """Stop the tunnel before removing the only user-facing controller."""
    set_tunnel_running(backend, tunnel_name, False)


def run_tray(tunnel_name: str, display_name: str = "Company VPN", *,
             drive_maps: tuple[DriveMapping, ...] = (),
             disconnect_on_office_dns: bool = False,
             instance_name: str = "CompanyVPNTray",
             window_class: str = "OmadaCompanyVpnTrayWindow") -> int:
    if sys.platform != "win32":
        return 2
    import win32api
    import win32con
    import win32event
    import win32gui
    import winerror

    mutex = win32event.CreateMutex(None, False, "Local\\" + instance_name)
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        return 0

    class CompanyVpnTray:
        WM_TRAY = win32con.WM_USER + 20
        CONNECT = 1001
        DISCONNECT = 1002
        EXIT = 1003

        def __init__(self) -> None:
            self.backend = WindowsWireGuardBackend()
            self.hinst = win32api.GetModuleHandle(None)
            self.class_name = window_class
            self.log_path = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "OmadaWireGuard" / "tray.log"
            mapping_state = self.log_path.parent / f"drive-maps-{tunnel_name}.json"
            self.drive_manager = DriveMappingManager(drive_maps, mapping_state)
            self.office_detector = OfficeDnsDetector(
                drive_maps, enabled=disconnect_on_office_dns)
            self.last_office_check = 0.0
            message_map = {
                win32con.WM_DESTROY: self._destroy,
                win32con.WM_CLOSE: self._close,
                win32con.WM_COMMAND: self._command,
                win32con.WM_TIMER: self._timer,
                self.WM_TRAY: self._tray_event,
            }
            window_definition = win32gui.WNDCLASS()
            window_definition.hInstance = self.hinst
            window_definition.lpszClassName = self.class_name
            window_definition.lpfnWndProc = message_map
            try:
                win32gui.RegisterClass(window_definition)
            except win32gui.error:
                pass
            self.hwnd = win32gui.CreateWindow(
                self.class_name, display_name, 0, 0, 0, 0, 0, 0, 0, self.hinst, None)
            ctypes.windll.user32.ChangeWindowMessageFilterEx(self.hwnd, self.WM_TRAY, 1, None)
            asset_root = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "assets"
            flags = win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE
            self.connected_icon = win32gui.LoadImage(
                0, str(asset_root / "omada-vpn-icon.ico"), win32con.IMAGE_ICON, 0, 0, flags)
            self.disconnected_icon = win32gui.LoadImage(
                0, str(asset_root / "omada-vpn-icon-disconnected.ico"), win32con.IMAGE_ICON, 0, 0, flags)
            self.last_status = ""
            self.drive_error: str | None = None
            try:
                self._sync_drives(self._status())
            except BackendError:
                pass
            self._notify(win32gui.NIM_ADD)
            ctypes.windll.user32.SetTimer(self.hwnd, 1, 3000, None)

        def _log(self, message: str) -> None:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as output:
                    output.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
            except OSError:
                pass

        def _status(self) -> str:
            try:
                return self.backend.status(tunnel_name)
            except BackendError:
                return "unavailable"

        def _sync_drives(self, status: str) -> None:
            try:
                if status == "running":
                    self.drive_manager.connect()
                elif status in {"stopped", "unavailable"}:
                    self.drive_manager.disconnect()
                self.drive_error = None
            except BackendError as exc:
                self.drive_error = str(exc)
                self._log(f"drive mapping failed: {exc}")
                raise

        def _notify(self, operation: int) -> None:
            status = self._status()
            labels = {
                "running": "Connected",
                "stopped": "Disconnected",
                "starting": "Connecting",
                "stopping": "Disconnecting",
                "unavailable": "Unavailable",
            }
            tip = f"{display_name} — {labels.get(status, status.capitalize())}"[:127]
            if self.drive_error:
                tip = f"{display_name} — {labels.get(status, status.capitalize())}; drive mapping failed"[:127]
            icon = self.connected_icon if status == "running" else self.disconnected_icon
            win32gui.Shell_NotifyIcon(operation, (
                self.hwnd, 0,
                win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP,
                self.WM_TRAY, icon, tip,
            ))
            self.last_status = status

        def _show_menu(self) -> None:
            status = self._status()
            menu = win32gui.CreatePopupMenu()
            win32gui.AppendMenu(menu, win32con.MF_STRING | win32con.MF_GRAYED,
                                0, f"Status: {status.capitalize()}")
            if self.drive_error:
                win32gui.AppendMenu(menu, win32con.MF_STRING | win32con.MF_GRAYED,
                                    0, "Drive mapping: retrying")
            win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
            connect_flags = win32con.MF_STRING
            disconnect_flags = win32con.MF_STRING | (win32con.MF_GRAYED if status not in {"running", "starting"} else 0)
            win32gui.AppendMenu(menu, connect_flags, self.CONNECT, "Connect / Reconnect")
            win32gui.AppendMenu(menu, disconnect_flags, self.DISCONNECT, "Disconnect")
            win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
            win32gui.AppendMenu(menu, win32con.MF_STRING, self.EXIT, "Exit tray")
            try:
                win32gui.SetForegroundWindow(self.hwnd)
            except win32gui.error:
                pass
            selected = win32gui.TrackPopupMenu(
                menu, win32con.TPM_LEFTALIGN | win32con.TPM_BOTTOMALIGN |
                win32con.TPM_RETURNCMD | win32con.TPM_NONOTIFY,
                *win32gui.GetCursorPos(), 0, self.hwnd, None)
            try:
                win32gui.PostMessage(self.hwnd, win32con.WM_NULL, 0, 0)
            except win32gui.error:
                pass
            win32gui.DestroyMenu(menu)
            if selected:
                self._execute_command(selected)

        def _set_running(self, running: bool) -> None:
            try:
                set_tunnel_running(self.backend, tunnel_name, running)
                self._sync_drives(self._status())
            except BackendError as exc:
                win32gui.MessageBox(self.hwnd, str(exc), display_name, win32con.MB_OK | win32con.MB_ICONERROR)
            self._notify(win32gui.NIM_MODIFY)

        def _execute_command(self, command: int) -> None:
            if command == self.CONNECT:
                self._set_running(True)
            elif command == self.DISCONNECT:
                self._set_running(False)
            elif command == self.EXIT:
                self._close(self.hwnd, 0, 0, 0)

        def _command(self, hwnd, msg, wparam, lparam):
            self._execute_command(win32api.LOWORD(wparam))
            return 0

        def _tray_event(self, hwnd, msg, wparam, lparam):
            try:
                event = win32api.LOWORD(lparam)
                self._log(f"notification event={event}")
                if event in (win32con.WM_RBUTTONUP, win32con.WM_CONTEXTMENU):
                    self._show_menu()
            except Exception:
                self._log("tray event failed:\n" + traceback.format_exc())
            return 0

        def _timer(self, hwnd, msg, wparam, lparam):
            status = self._status()
            now = time.monotonic()
            if status == "running" and now - self.last_office_check >= 15:
                self.last_office_check = now
                try:
                    if self.office_detector.is_on_office_network(tunnel_name):
                        self._log("office DNS suffix detected on a non-WireGuard adapter; disconnecting VPN")
                        self.backend.stop(tunnel_name)
                except Exception:
                    self._log("office DNS detection failed:\n" + traceback.format_exc())
            if status != self.last_status or self.drive_error:
                try:
                    self._sync_drives(status)
                except BackendError:
                    pass
                self._notify(win32gui.NIM_MODIFY)
            return 0

        def _destroy(self, hwnd, msg, wparam, lparam):
            ctypes.windll.user32.KillTimer(self.hwnd, 1)
            win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (self.hwnd, 0))
            win32gui.PostQuitMessage(0)
            return 0

        def _close(self, hwnd, msg, wparam, lparam):
            try:
                stop_tunnel_on_tray_exit(self.backend, tunnel_name)
            except BackendError as exc:
                self._log(f"VPN stop during tray shutdown failed: {exc}")
                win32gui.MessageBox(
                    self.hwnd,
                    f"The VPN could not be stopped. The tray will remain open.\n\n{exc}",
                    display_name,
                    win32con.MB_OK | win32con.MB_ICONERROR,
                )
                return 0
            try:
                self.drive_manager.disconnect()
            except BackendError as exc:
                self._log(f"drive restore during tray shutdown failed: {exc}")
            win32gui.DestroyWindow(self.hwnd)
            return 0

        def run(self) -> None:
            win32gui.PumpMessages()

    app = CompanyVpnTray()
    app.run()
    win32api.CloseHandle(mutex)
    return 0
