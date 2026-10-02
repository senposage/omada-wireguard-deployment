from __future__ import annotations

import json
import re
import threading
import sys
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .credentials import CloudCredentials
from .cloud_discovery import CloudController, CloudDiscoveryClient
from .deployment_setup import DeploymentTarget, routes, write_deployment
from .drive_mapping import DriveMapping, parse_drive_maps
from .errors import EnrollmentError
from .package_builder import build_self_extracting


class SetupWizard:
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.root = tk.Tk()
        self.root.title("Company VPN Deployment Builder")
        self.root.geometry("860x930")
        self.root.minsize(760, 820)
        icon_roots = [Path(getattr(sys, "_MEIPASS", "")), Path(__file__).resolve().parents[2]]
        for root in icon_roots:
            icon = root / "assets" / "omada-vpn-icon.png"
            if icon.is_file():
                self.root._app_icon = tk.PhotoImage(file=str(icon))
                self.root.iconphoto(True, self.root._app_icon)
                break
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("AppTitle.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("AppSubtitle.TLabel", font=("Segoe UI", 10), foreground="#52606d")
        self.discovery: CloudDiscoveryClient | None = None
        self.controllers: list[CloudController] = []
        self.sites: list[dict[str, Any]] = []
        self.servers: list[dict[str, Any]] = []
        self.profile_selection: dict[str, str] = {}
        self.drive_mappings: list[DriveMapping] = []
        self.vars = {name: tk.StringVar(value=value) for name, value in {
            "email": "", "password": "", "controller": "", "site": "", "server": "",
            "endpoint": "", "dns": "", "route": "Site networks", "routes": "",
            "keepalive": "", "mtu": "", "tunnel": "omada",
            "name_mode": "Computer and user", "custom_name": "",
            "office_disconnect": "0",
            "output": str(((Path(sys.executable).resolve().parent if getattr(sys, "frozen", False)
                            else Path.cwd() / "outputs") / f"Omada-WireGuard-Deployment-{__version__}.exe").resolve()),
            "status": "Enter the Omada Cloud administrator login, then discover controllers.",
        }.items()}
        self._build()

    def _row(self, parent, row: int, label: str, key: str, *, password: bool = False):
        self.ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=6)
        entry = self.ttk.Entry(parent, textvariable=self.vars[key], show="•" if password else "")
        entry.grid(row=row, column=1, sticky="ew", pady=6)
        return entry

    def _build(self) -> None:
        tk, ttk = self.tk, self.ttk
        outer = ttk.Frame(self.root, padding=22)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        ttk.Label(outer, text="Create a managed VPN installer", style="AppTitle.TLabel").grid(sticky="w")
        ttk.Label(
            outer,
            text="Sign in to Omada Cloud, choose a site, and build one ready-to-run Windows installer.",
            style="AppSubtitle.TLabel",
        ).grid(sticky="w", pady=(3, 16))

        cloud = ttk.LabelFrame(outer, text="Omada Cloud", padding=14)
        cloud.grid(sticky="ew", pady=5)
        cloud.columnconfigure(1, weight=1)
        self._row(cloud, 0, "Administrator email", "email")
        self._row(cloud, 1, "Password", "password", password=True)
        self.discover_button = ttk.Button(cloud, text="Sign in", command=self.discover)
        self.discover_button.grid(row=2, column=1, sticky="e", pady=(8, 2))
        ttk.Label(cloud, text="Controller").grid(row=3, column=0, sticky="w", pady=6)
        self.controller_box = ttk.Combobox(cloud, textvariable=self.vars["controller"], state="readonly")
        self.controller_box.grid(row=3, column=1, sticky="ew", pady=6)
        self.controller_box.bind("<<ComboboxSelected>>", lambda _: self.load_sites())
        ttk.Label(cloud, text="Site").grid(row=4, column=0, sticky="w", pady=6)
        self.site_box = ttk.Combobox(cloud, textvariable=self.vars["site"], state="readonly")
        self.site_box.grid(row=4, column=1, sticky="ew", pady=6)
        self.site_box.bind("<<ComboboxSelected>>", lambda _: self.load_servers())
        ttk.Label(cloud, text="WireGuard server").grid(row=5, column=0, sticky="w", pady=6)
        self.server_box = ttk.Combobox(cloud, textvariable=self.vars["server"], state="readonly")
        self.server_box.grid(row=5, column=1, sticky="ew", pady=6)
        self.server_box.bind("<<ComboboxSelected>>", lambda _: self.populate_endpoint())

        network = ttk.LabelFrame(outer, text="Client network settings", padding=14)
        network.grid(sticky="ew", pady=9)
        network.columnconfigure(1, weight=1)
        self._row(network, 0, "Public gateway / DDNS", "endpoint")
        self._row(network, 1, "DNS server", "dns")
        ttk.Label(network, text="Traffic routing").grid(row=2, column=0, sticky="w", pady=6)
        route_box = ttk.Combobox(network, textvariable=self.vars["route"], state="readonly",
                                 values=("Site networks", "Custom IPs / networks", "Full tunnel"))
        route_box.grid(row=2, column=1, sticky="ew", pady=6)
        route_box.bind("<<ComboboxSelected>>", lambda _: self._route_changed())
        self.route_description = ttk.Label(network, foreground="#52606d", wraplength=520)
        self.route_description.grid(row=3, column=1, sticky="w", pady=(0, 4))
        self.routes_label = ttk.Label(network, text="Custom IPs / networks")
        self.routes_label.grid(row=4, column=0, sticky="w", padx=(0, 12), pady=6)
        self.routes_entry = ttk.Entry(network, textvariable=self.vars["routes"])
        self.routes_entry.grid(row=4, column=1, sticky="ew", pady=6)
        self.routes_help = ttk.Label(
            network, text="Comma-separated; a single IP is routed as /32.", foreground="#52606d")
        self.routes_help.grid(row=5, column=1, sticky="w")
        self._row(network, 6, "Keepalive override", "keepalive")
        self._row(network, 7, "MTU override", "mtu")
        self._row(network, 8, "Tunnel name", "tunnel")
        ttk.Label(network, text="Omada client identity").grid(row=9, column=0, sticky="w", pady=6)
        name_box = ttk.Combobox(network, textvariable=self.vars["name_mode"], state="readonly",
                                values=("Computer and user", "Computer only", "Fixed custom name"))
        name_box.grid(row=9, column=1, sticky="ew", pady=6)
        name_box.bind("<<ComboboxSelected>>", lambda _: self._name_mode_changed())
        self.custom_name_label = ttk.Label(network, text="Fixed custom name")
        self.custom_name_label.grid(row=10, column=0, sticky="w", padx=(0, 12), pady=6)
        self.custom_name_entry = ttk.Entry(network, textvariable=self.vars["custom_name"])
        self.custom_name_entry.grid(row=10, column=1, sticky="ew", pady=6)
        self.name_help = ttk.Label(
            network, text="Default example: DESKTOP_NAME_ben", foreground="#52606d")
        self.name_help.grid(row=11, column=1, sticky="w")
        self.office_disconnect = tk.BooleanVar(value=False)
        self.remove_credentials = tk.BooleanVar(value=False)
        self._route_changed()
        self._name_mode_changed()

        drives = ttk.LabelFrame(outer, text="Drive mappings", padding=14)
        drives.grid(sticky="ew", pady=5)
        drives.columnconfigure(1, weight=1)
        drives.columnconfigure(2, weight=1)
        drives.columnconfigure(3, weight=1)
        self.map_tree = ttk.Treeview(
            drives, columns=("letter", "vpn", "lan"), show="headings", height=3)
        for column, heading, width in (
                ("letter", "Drive", 70), ("vpn", "VPN / FQDN share", 310),
                ("lan", "LAN restore share", 310)):
            self.map_tree.heading(column, text=heading)
            self.map_tree.column(column, width=width, stretch=column != "letter")
        self.map_tree.grid(row=0, column=0, columnspan=5, sticky="ew")
        self.map_tree.bind("<<TreeviewSelect>>", self._select_drive_mapping)
        self.map_letter = tk.StringVar(value="X:")
        self.map_vpn_path = tk.StringVar()
        self.map_lan_path = tk.StringVar()
        ttk.Label(drives, text="Drive").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Combobox(
            drives, textvariable=self.map_letter, state="readonly", width=6,
            values=tuple(f"{letter}:" for letter in "DEFGHIJKLMNOPQRSTUVWXYZ"),
        ).grid(row=2, column=0, sticky="w")
        ttk.Label(drives, text="VPN / FQDN share").grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Entry(drives, textvariable=self.map_vpn_path).grid(row=2, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(drives, text="LAN restore share (optional)").grid(row=1, column=2, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Entry(drives, textvariable=self.map_lan_path).grid(row=2, column=2, sticky="ew", padx=(8, 0))
        buttons = ttk.Frame(drives)
        buttons.grid(row=2, column=3, columnspan=2, padx=(8, 0))
        ttk.Button(buttons, text="Add / update", command=self._save_drive_mapping).pack(side="left")
        ttk.Button(buttons, text="Remove", command=self._remove_drive_mapping).pack(side="left", padx=(6, 0))
        ttk.Label(
            drives, text="The VPN path is used while connected. LAN restore is optional: a blank field restores the previous mapping when one exists, otherwise does nothing.",
            foreground="#52606d",
        ).grid(row=3, column=1, columnspan=3, sticky="w", pady=(5, 0))
        ttk.Checkbutton(
            drives, text="Disconnect VPN when the office DNS suffix is present",
            variable=self.office_disconnect,
        ).grid(row=4, column=1, columnspan=3, sticky="w", pady=(4, 0))
        ttk.Checkbutton(
            drives, text="Delete deployment credentials after enrollment (manual Omada peer removal)",
            variable=self.remove_credentials,
        ).grid(row=5, column=1, columnspan=3, sticky="w", pady=(4, 0))

        package = ttk.LabelFrame(outer, text="Deployment output", padding=14)
        package.grid(sticky="ew", pady=5)
        package.columnconfigure(1, weight=1)
        self._row(package, 0, "Deployment executable", "output")
        ttk.Button(package, text="Browse…", command=self.browse).grid(row=0, column=2, padx=(8, 0))
        self.build_button = ttk.Button(package, text="Build deployment EXE", command=self.generate, state="disabled")
        self.build_button.grid(row=1, column=1, sticky="e", pady=(8, 2))
        profile_buttons = ttk.Frame(package)
        profile_buttons.grid(row=2, column=1, sticky="e", pady=(8, 0))
        ttk.Button(profile_buttons, text="Load configuration…", command=self.load_profile).pack(side="left")
        ttk.Button(profile_buttons, text="Save configuration…", command=self.save_profile).pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(outer, mode="indeterminate")
        self.progress.grid(sticky="ew", pady=(14, 5))
        ttk.Label(outer, textvariable=self.vars["status"], wraplength=700).grid(sticky="w")

    def browse(self) -> None:
        from tkinter import filedialog
        selected = filedialog.asksaveasfilename(parent=self.root, title="Save deployment executable",
                                                defaultextension=".exe",
                                                filetypes=(("Windows executable", "*.exe"),))
        if selected:
            self.vars["output"].set(selected)

    def _refresh_drive_mapping_tree(self) -> None:
        for item in self.map_tree.get_children():
            self.map_tree.delete(item)
        for mapping in self.drive_mappings:
            self.map_tree.insert("", "end", iid=mapping.letter, values=(
                mapping.letter, mapping.path, mapping.restore_path or ""))

    def _select_drive_mapping(self, _event=None) -> None:
        selected = self.map_tree.selection()
        if not selected:
            return
        mapping = next((item for item in self.drive_mappings if item.letter == selected[0]), None)
        if mapping:
            self.map_letter.set(mapping.letter)
            self.map_vpn_path.set(mapping.path)
            self.map_lan_path.set(mapping.restore_path or "")

    def _save_drive_mapping(self) -> None:
        from tkinter import messagebox
        try:
            # Reuse the parser solely as validation for one structured row.
            entry = f"{self.map_letter.get()}={self.map_vpn_path.get()}"
            if self.map_lan_path.get().strip():
                entry += f" | {self.map_lan_path.get()}"
            mapping = parse_drive_maps(entry)[0]
        except (EnrollmentError, IndexError) as exc:
            messagebox.showerror("Invalid drive mapping", str(exc), parent=self.root)
            return
        self.drive_mappings = [item for item in self.drive_mappings if item.letter != mapping.letter]
        self.drive_mappings.append(mapping)
        self.drive_mappings.sort(key=lambda item: item.letter)
        self._refresh_drive_mapping_tree()

    def _remove_drive_mapping(self) -> None:
        selected = self.map_tree.selection()
        if not selected:
            return
        self.drive_mappings = [item for item in self.drive_mappings if item.letter != selected[0]]
        self._refresh_drive_mapping_tree()
        self.map_vpn_path.set("")
        self.map_lan_path.set("")

    @staticmethod
    def output_for_site(path: str | Path, site_name: str) -> Path:
        output = Path(path).resolve()
        if output.suffix.casefold() != ".exe":
            output = output.with_suffix(".exe")
        safe_site = re.sub(r"[^A-Za-z0-9]+", "_", site_name).strip("_") or "Site"
        suffix = f"-{safe_site}"
        stem = output.stem
        if not stem.casefold().endswith(suffix.casefold()):
            stem += suffix
        return output.with_name(stem + ".exe")

    def save_profile(self) -> None:
        from tkinter import filedialog, messagebox
        selected = filedialog.asksaveasfilename(
            parent=self.root, title="Save generator configuration",
            defaultextension=".json", filetypes=(("Generator configuration", "*.json"),))
        if not selected:
            return
        values = {key: self.vars[key].get() for key in (
            "email", "endpoint", "dns", "route", "routes", "keepalive", "mtu",
            "tunnel", "name_mode", "custom_name", "output")}
        values["drive_maps"] = [
            {"letter": item.letter, "path": item.path, "restore_path": item.restore_path}
            for item in self.drive_mappings
        ]
        values["office_disconnect"] = self.office_disconnect.get()
        values["remove_credentials_after_enroll"] = self.remove_credentials.get()
        profile = {
            "version": 1,
            "values": values,
            "controller_name": (self.controllers[self.controller_box.current()].name
                                if self.controller_box.current() >= 0 else self.profile_selection.get("controller_name", "")),
            "site_name": (str(self.sites[self.site_box.current()].get("name") or "")
                          if self.site_box.current() >= 0 else self.profile_selection.get("site_name", "")),
            "server_name": (str(self.servers[self.server_box.current()].get("name") or "")
                            if self.server_box.current() >= 0 else self.profile_selection.get("server_name", "")),
        }
        try:
            Path(selected).write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Cannot save configuration", str(exc), parent=self.root)
            return
        self.vars["status"].set(f"Generator configuration saved to {selected}")

    def load_profile(self) -> None:
        from tkinter import filedialog, messagebox
        selected = filedialog.askopenfilename(
            parent=self.root, title="Load generator configuration",
            filetypes=(("Generator configuration", "*.json"), ("All files", "*.*")))
        if not selected:
            return
        try:
            profile = json.loads(Path(selected).read_text(encoding="utf-8"))
            if profile.get("version") != 1 or not isinstance(profile.get("values"), dict):
                raise EnrollmentError("Unsupported generator configuration format")
        except (OSError, json.JSONDecodeError, EnrollmentError) as exc:
            messagebox.showerror("Cannot load configuration", str(exc), parent=self.root)
            return
        for key, value in profile["values"].items():
            if key in self.vars and key not in {"password", "status"}:
                self.vars[key].set(str(value or ""))
        saved_maps = profile["values"].get("drive_maps", [])
        try:
            if isinstance(saved_maps, str):
                self.drive_mappings = parse_drive_maps(saved_maps)
            else:
                self.drive_mappings = [DriveMapping(
                    str(item["letter"]), str(item["path"]),
                    str(item.get("restore_path") or "") or None)
                    for item in saved_maps]
        except (TypeError, KeyError, EnrollmentError) as exc:
            messagebox.showerror("Cannot load configuration", f"Invalid drive mappings: {exc}", parent=self.root)
            return
        self._refresh_drive_mapping_tree()
        self.office_disconnect.set(bool(profile["values"].get("office_disconnect", False)))
        self.remove_credentials.set(bool(profile["values"].get("remove_credentials_after_enroll", False)))
        self.profile_selection = {
            key: str(profile.get(key) or "") for key in
            ("controller_name", "site_name", "server_name")
        }
        self._route_changed()
        self._name_mode_changed()
        if self.discovery and self.controllers:
            self._select_controller()
        self.vars["status"].set(
            "Configuration loaded. Enter the Omada password and sign in to refresh controllers and sites.")

    @staticmethod
    def _named_index(items: list[Any], name: str) -> int:
        for index, item in enumerate(items):
            item_name = item.name if hasattr(item, "name") else str(item.get("name") or "")
            if item_name.casefold() == name.casefold():
                return index
        return 0

    def _select_controller(self) -> None:
        if not self.controllers:
            return
        self.controller_box.current(self._named_index(
            self.controllers, self.profile_selection.get("controller_name", "")))
        self.load_sites()

    def _route_changed(self) -> None:
        selected = self.vars["route"].get()
        descriptions = {
            "Site networks": "Route the networks selected on the Omada WireGuard server through the VPN.",
            "Custom IPs / networks": "Route only the individual IP addresses or CIDR networks entered below.",
            "Full tunnel": "Route all IPv4 and IPv6 traffic, including internet traffic, through the VPN.",
        }
        self.route_description.configure(text=descriptions.get(selected, ""))
        widgets = (self.routes_label, self.routes_entry, self.routes_help)
        if selected == "Custom IPs / networks":
            for widget in widgets:
                widget.grid()
        else:
            for widget in widgets:
                widget.grid_remove()

    def _name_mode_changed(self) -> None:
        custom = self.vars["name_mode"].get() == "Fixed custom name"
        for widget in (self.custom_name_label, self.custom_name_entry):
            widget.grid() if custom else widget.grid_remove()
        self.name_help.configure(
            text=("Enter one fixed Omada peer name for this deployment."
                  if custom else "Example: DESKTOP_NAME_ben or DESKTOP_DOMAIN_ben"))

    @staticmethod
    def _label(item: dict[str, Any]) -> str:
        return f"{item.get('name') or '(unnamed)'}  [{item.get('id') or item.get('siteId')}]"

    def _busy(self, value: bool) -> None:
        self.discover_button.configure(state="disabled" if value else "normal")
        self.build_button.configure(
            state="disabled" if value or not self.servers else "normal")
        if value:
            self.progress.start(12)
        else:
            self.progress.stop()

    def discover(self) -> None:
        from tkinter import messagebox
        email, password = self.vars["email"].get().strip(), self.vars["password"].get()
        if not email or not password:
            messagebox.showerror("Missing login", "Enter the Omada Cloud administrator email and password.", parent=self.root)
            return
        self._busy(True)
        self.vars["status"].set("Signing in and querying Omada Cloud…")

        def worker():
            try:
                discovery = CloudDiscoveryClient(CloudCredentials(email, password))
                controllers = discovery.controllers()
            except Exception as exc:
                self.root.after(0, lambda detail=str(exc): self._error(detail))
            else:
                self.root.after(0, lambda: self._controllers_ready(discovery, controllers))
        threading.Thread(target=worker, daemon=True).start()

    def _error(self, detail: str) -> None:
        from tkinter import messagebox
        self._busy(False)
        self.vars["status"].set("Discovery did not complete.")
        messagebox.showerror("Omada deployment generator", detail, parent=self.root)

    def _controllers_ready(self, discovery: CloudDiscoveryClient, controllers: list[CloudController]) -> None:
        self.discovery, self.controllers = discovery, controllers
        labels = [f"{item.name} — {item.model} ({item.version})" for item in controllers]
        self.controller_box.configure(values=labels)
        if labels:
            self._select_controller()
        self._busy(False)
        self.vars["status"].set(f"Found {len(labels)} controller(s). Select the target controller and site.")

    def load_sites(self) -> None:
        if not self.discovery or self.controller_box.current() < 0:
            return
        try:
            self.sites = self.discovery.sites(self.controllers[self.controller_box.current()])
        except Exception as exc:
            self._error(str(exc))
            return
        labels = [self._label(item) for item in self.sites]
        self.site_box.configure(values=labels)
        if labels:
            self.site_box.current(self._named_index(
                self.sites, self.profile_selection.get("site_name", "")))
            self.load_servers()
        self.vars["status"].set(f"Found {len(labels)} site(s). Select the site and WireGuard server.")

    def load_servers(self) -> None:
        if not self.discovery or self.controller_box.current() < 0 or self.site_box.current() < 0:
            return
        site = self.sites[self.site_box.current()]
        site_id = str(site.get("id") or site.get("siteId") or "")
        try:
            controller = self.controllers[self.controller_box.current()]
            self.servers = self.discovery.wireguard_servers(controller, site_id)
        except Exception as exc:
            self._error(str(exc))
            return
        labels = [self._label(item) for item in self.servers]
        self.server_box.configure(values=labels)
        self.vars["status"].set(f"Found {len(labels)} WireGuard server(s) for this site.")
        if labels:
            self.server_box.current(self._named_index(
                self.servers, self.profile_selection.get("server_name", "")))
            self.build_button.configure(state="normal")
            self.populate_endpoint()
        else:
            self.build_button.configure(state="disabled")

    def populate_endpoint(self) -> None:
        if (not self.discovery or self.controller_box.current() < 0 or
                self.site_box.current() < 0 or self.server_box.current() < 0):
            return
        controller = self.controllers[self.controller_box.current()]
        site = self.sites[self.site_box.current()]
        site_id = str(site.get("id") or site.get("siteId") or "")
        server = self.servers[self.server_box.current()]
        try:
            endpoint = self.discovery.wireguard_endpoint(controller, site_id, server)
        except Exception as exc:
            self.vars["status"].set(
                f"Could not read the selected WAN address: {exc}. Enter an endpoint manually."
            )
            return
        if endpoint:
            self.vars["endpoint"].set(endpoint)
            self.vars["status"].set(f"Loaded public gateway {endpoint} from the selected Omada WAN.")
        else:
            self.vars["status"].set(
                "Omada did not report an address for the selected WAN. Enter a public IP or DDNS name."
            )

    @staticmethod
    def _optional_int(value: str, name: str) -> int | None:
        if not value.strip():
            return None
        try:
            number = int(value)
        except ValueError as exc:
            raise EnrollmentError(f"{name} must be a whole number") from exc
        if number <= 0:
            raise EnrollmentError(f"{name} must be greater than zero")
        return number

    def generate(self) -> None:
        from tkinter import messagebox
        temporary: Path | None = None
        try:
            if self.controller_box.current() < 0 or self.site_box.current() < 0 or self.server_box.current() < 0:
                raise EnrollmentError("Select a controller, site, and WireGuard server")
            endpoint = self.vars["endpoint"].get().strip()
            if not endpoint:
                raise EnrollmentError("Enter the public gateway IP or DDNS hostname")
            route_mode = {
                "Site networks": "site",
                "Custom IPs / networks": "custom",
                "Full tunnel": "full",
            }.get(self.vars["route"].get())
            if not route_mode:
                raise EnrollmentError("Select a traffic routing option")
            allowed_routes = routes(route_mode, self.vars["routes"].get())
            drive_maps = list(self.drive_mappings)
            if self.office_disconnect.get() and not any(
                    "." in mapping.path[2:].split("\\", 1)[0] for mapping in drive_maps):
                raise EnrollmentError(
                    "Office DNS auto-disconnect requires at least one FQDN drive mapping")
            credentials = CloudCredentials(self.vars["email"].get().strip(), self.vars["password"].get())
            controller = self.controllers[self.controller_box.current()]
            target = DeploymentTarget(controller.device_id, controller.omada_id,
                                      self.discovery.user_id(controller), controller.connector_url,
                                      controller.name)
            selected_site = self.sites[self.site_box.current()]
            output_exe = self.output_for_site(
                self.vars["output"].get(), str(selected_site.get("name") or "Site"))
            self.vars["output"].set(str(output_exe))
            temporary = Path(tempfile.mkdtemp(prefix="omada-wg-generator-"))
            settings = write_deployment(
                temporary / "deployment.json", target,
                selected_site, self.servers[self.server_box.current()], credentials,
                route_mode=route_mode, allowed_ips=allowed_routes, endpoint=endpoint,
                dns=self.vars["dns"].get().strip() or None,
                keepalive=self._optional_int(self.vars["keepalive"].get(), "Keepalive"),
                mtu=self._optional_int(self.vars["mtu"].get(), "MTU"),
                tunnel_name=self.vars["tunnel"].get().strip() or "omada",
                client_name_mode={
                    "Computer and user": "computer_user",
                    "Computer only": "computer",
                    "Fixed custom name": "custom",
                }.get(self.vars["name_mode"].get(), "computer_user"),
                client_custom_name=self.vars["custom_name"].get().strip() or None,
                drive_maps=drive_maps,
                disconnect_on_office_dns=self.office_disconnect.get(),
                remove_credentials_after_enroll=self.remove_credentials.get(),
            )
        except Exception as exc:
            if temporary:
                shutil.rmtree(temporary, ignore_errors=True)
            messagebox.showerror("Cannot generate deployment", str(exc), parent=self.root)
            return
        self._busy(True)
        self.vars["status"].set("Building the runnable deployment package and downloading WireGuard…")

        def worker() -> None:
            try:
                executable = build_self_extracting(settings, output_exe)
            except Exception as exc:
                self.root.after(0, lambda detail=str(exc): self._package_error(detail))
            else:
                self.root.after(0, lambda: self._package_ready(executable))
            finally:
                shutil.rmtree(temporary, ignore_errors=True)

        threading.Thread(target=worker, daemon=False).start()

    def _package_error(self, detail: str) -> None:
        from tkinter import messagebox
        self._busy(False)
        self.vars["status"].set("Deployment package build failed.")
        messagebox.showerror("Cannot build deployment package", detail, parent=self.root)

    def _package_ready(self, executable: Path) -> None:
        from tkinter import messagebox
        self._busy(False)
        self.vars["status"].set(f"Runnable deployment executable saved to {executable}")
        messagebox.showinfo(
            "Deployment package ready",
            f"Distribute this file:\n{executable}\n\nThe user only needs to double-click it.",
            parent=self.root,
        )

    def run(self) -> int:
        self.root.mainloop()
        return 0


def main() -> int:
    return SetupWizard().run()


if __name__ == "__main__":
    raise SystemExit(main())
