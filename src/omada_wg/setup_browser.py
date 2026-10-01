from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import EnrollmentError
from .credentials import CloudCredentials, CredentialStore, PortableCredentialStore
from .secretstore import DpapiSessionStore
from .session import CloudCredentialSessionProvider

CLOUD_ORIGIN = "https://use1-omada-cloud.tplinkcloud.com"
CONNECTOR = "https://use1-api-omada-controller-connector.tplinkcloud.com"
_BROWSER_API = re.compile(r"/omadac/([^/]+)/([^/]+)/api/v2/")
_OPEN_API = re.compile(r"/omadac/([^/]+)/openapi/v2/([^/]+)/")


@dataclass
class CapturedSession:
    device_id: str = ""
    omada_id: str = ""
    csrf_token: str = ""
    user_id: str = ""
    requests_seen: int = 0
    event: threading.Event = field(default_factory=threading.Event)

    def observe(self, request: Any) -> None:
        self.requests_seen += 1
        match = _BROWSER_API.search(request.url) or _OPEN_API.search(request.url)
        if match:
            self.device_id, self.omada_id = match.group(1), match.group(2)
        headers = request.headers
        self.csrf_token = headers.get("csrf-token", self.csrf_token)
        self.user_id = headers.get("user-id", self.user_id)
        if self.device_id and self.omada_id and self.csrf_token and self.user_id:
            self.event.set()


class DiscoveryClient:
    def __init__(self, session: dict[str, str]):
        self.session = session

    def get(self, url: str) -> Any:
        headers = {
            "Cookie": self.session["cookie"], "csrf-token": self.session["csrf_token"],
            "user-id": self.session["user_id"], "omada-request-source": "web-remote",
            "X-Requested-With": "XMLHttpRequest", "Origin": self.session["origin"],
            "Referer": self.session["origin"] + "/", "refresh": "manual", "request-hash": "#VPN",
        }
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
                value = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise EnrollmentError(f"Cloud discovery request failed: {exc}") from exc
        if value.get("errorCode") != 0:
            raise EnrollmentError(value.get("msg") or value.get("errorMsg") or "Cloud discovery failed")
        return value.get("result")

    @staticmethod
    def items(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("data", "list", "items", "records"):
                if isinstance(result.get(key), list):
                    return result[key]
        raise EnrollmentError("TP-Link returned an unexpected list response")


def _choose(label: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    if not items:
        raise EnrollmentError(f"No {label} found")
    if len(items) == 1:
        return items[0]
    print(f"\nChoose {label}:")
    for index, item in enumerate(items, 1):
        name = item.get("name") or "(unnamed)"
        identifier = item.get("id") or item.get("siteId") or "unknown-id"
        print(f"  {index}. {name}  [{identifier}]")
    while True:
        try:
            selected = int(input("Selection: "))
            return items[selected - 1]
        except (ValueError, IndexError):
            print("Enter one of the listed numbers.")


def _attempt_browser_login(page: Any, credentials: CloudCredentials) -> bool:
    """Fill TP-Link's current login form; leave exceptional challenges to the user."""
    try:
        page.wait_for_url(re.compile(r"https://id\.tplinkcloud\.com/.*"), timeout=20_000)
        # TP-Link currently includes a hidden anti-autofill password input before
        # the real control, so broad input[type=password] selection is incorrect.
        email = page.locator("#form_item_email")
        password = page.locator("#form_item_password")
        email.wait_for(state="visible", timeout=20_000)
        email.fill(credentials.username)
        password.fill(credentials.password)
        submit = page.locator('a[title="Sign In"]:not(.is-disabled)')
        submit.wait_for(state="visible", timeout=10_000)
        submit.click()
        return True
    except Exception:
        return False


def _capture(timeout: int, credentials: CloudCredentials | None = None) -> tuple[CapturedSession, dict[str, str]]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise EnrollmentError("Browser setup support is not installed. Run: py -m pip install -e .[setup]") from exc
    captured = CapturedSession()
    authenticated_cookies = None
    direct_login_error = None
    if credentials:
        try:
            bootstrap = CloudCredentialSessionProvider(None, credentials=credentials)
            authenticated_cookies = bootstrap.browser_cookies()
        except EnrollmentError as exc:
            direct_login_error = str(exc)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=False)
        context = browser.new_context()
        if authenticated_cookies:
            context.add_cookies(authenticated_cookies)
        # Controller launch opens a new tab. Listen at the context level so the
        # authenticated API traffic is observed regardless of which tab sends it.
        context.on("request", captured.observe)
        page = context.new_page()
        page.goto(CLOUD_ORIGIN, wait_until="domcontentloaded")
        if authenticated_cookies:
            print("Omada Cloud login completed. Open the target controller.")
        else:
            page.wait_for_timeout(2500)
            automatic = _attempt_browser_login(page, credentials) if credentials else False
            if automatic:
                print("TP-Link sign-in submitted. Complete any requested verification, then open the target controller.")
            else:
                detail = f" Direct login response: {direct_login_error}" if direct_login_error else ""
                print("A TP-Link Cloud window is open. Sign in, then open the target controller." + detail)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not captured.event.is_set():
            # The Cloud portal can replace or close its original page while
            # launching a controller. Do not tie capture lifetime to that page.
            time.sleep(0.5)
        if not captured.event.is_set():
            browser.close()
            raise EnrollmentError("Timed out before an authenticated target-controller session was detected")
        cookies = context.cookies()
        cookie = "; ".join(f"{x['name']}={x['value']}" for x in cookies if x.get("value"))
        csrf_cookie = next((x["value"] for x in cookies if x["name"].lower() == "csrftoken"), "")
        session = {
            "cookie": cookie,
            "csrf_token": captured.csrf_token or csrf_cookie,
            "user_id": captured.user_id,
            "origin": CLOUD_ORIGIN,
        }
        try:
            confirmation = context.pages[-1]
            confirmation.set_content("""
                <!doctype html><html><body style="margin:0;background:#f4f7fb;font-family:Segoe UI,sans-serif">
                <main style="max-width:680px;margin:12vh auto;padding:48px;background:white;border-radius:16px;
                            box-shadow:0 12px 40px #18315322;text-align:center">
                  <div style="font-size:52px;color:#16845b">&#10003;</div>
                  <h1 style="color:#183153">Controller captured successfully</h1>
                  <p style="font-size:18px;color:#52606d;line-height:1.5">
                    The deployment generator found the selected Omada controller.<br>
                    This secure setup window will now close automatically.
                  </p>
                </main></body></html>
            """)
            confirmation.bring_to_front()
            confirmation.wait_for_timeout(2500)
        except Exception:
            # Confirmation is cosmetic; successful capture must not fail if a tab closed.
            pass
        browser.close()
    if not all(session.values()):
        raise EnrollmentError("The browser session was detected but required session fields were missing")
    return captured, session


def _routes(mode: str, value: str | None) -> list[str]:
    if mode != "custom":
        return []
    entries = [entry.strip() for entry in (value or "").split(",") if entry.strip()]
    if not entries:
        raise EnrollmentError("Custom routing requires at least one IP address or network")
    try:
        return [str(ipaddress.ip_network(entry, strict=False)) for entry in entries]
    except ValueError as exc:
        raise EnrollmentError(f"Invalid custom route: {exc}") from exc


def discover_sites(timeout: int, credentials: CloudCredentials | None = None) -> tuple[CapturedSession, dict[str, str], list[dict[str, Any]]]:
    captured, session = _capture(timeout, credentials)
    client = DiscoveryClient(session)
    browser_root = f"{CONNECTOR}/omadac/{captured.device_id}/{captured.omada_id}/api/v2"
    sites = client.items(client.get(browser_root + "/sites?currentPage=1&currentPageSize=100"))
    return captured, session, sites


def discover_servers(captured: CapturedSession, session: dict[str, str], site_id: str) -> list[dict[str, Any]]:
    client = DiscoveryClient(session)
    vpn_url = (f"{CONNECTOR}/omadac/{captured.device_id}/openapi/v2/{captured.omada_id}/sites/"
               f"{urllib.parse.quote(site_id, safe='')}/vpn/client-to-site-vpn-servers?page=1&pageSize=100")
    return [x for x in client.items(client.get(vpn_url)) if x.get("vpnType") == 4]


def write_deployment(output: Path, captured: CapturedSession, session: dict[str, str],
                     site: dict[str, Any], server: dict[str, Any], credentials: CloudCredentials | None,
                     *, route_mode: str = "site", allowed_ips: list[str] | None = None,
                     endpoint: str = "REPLACE_WITH_PUBLIC_IP_OR_DDNS", dns: str | None = None,
                     keepalive: int | None = None, mtu: int | None = None,
                     tunnel_name: str = "omada", client_name_mode: str = "computer_user",
                     client_custom_name: str | None = None,
                     connector_base_url: str = CONNECTOR) -> Path:
    site_id = str(site.get("id") or site.get("siteId") or "")
    if not site_id:
        raise EnrollmentError("Selected site did not contain an ID")
    output = output.resolve()
    session_path = output.with_suffix(".session.dpapi")
    credentials_path = output.with_suffix(".credentials.bin")
    DpapiSessionStore(session_path).save(session)
    credential_key = None
    if credentials is not None:
        key = PortableCredentialStore.generate_key()
        PortableCredentialStore(credentials_path, key).save(credentials)
        credential_key = PortableCredentialStore.encode_key(key)
    deployment = {
        "connector_base_url": connector_base_url,
        "device_id": captured.device_id,
        "omada_id": captured.omada_id,
        "site_id": site_id,
        "user_id": captured.user_id,
        "server_id": str(server["id"]),
        "server_name": server.get("name", ""),
        "endpoint_fallback": endpoint,
        "dns": dns,
        "route_mode": route_mode,
        "allowed_ips": allowed_ips or [],
        "keepalive": keepalive,
        "mtu": mtu,
        "tunnel_name": tunnel_name,
        "client_name_mode": client_name_mode,
        "client_custom_name": client_custom_name,
        "state_path": r"%ProgramData%\OmadaWireGuard\enrollment.json",
        "session_file": session_path.name,
        "credentials_file": credentials_path.name if credentials is not None else None,
        "credential_key": credential_key,
        "wireguard_msi_dir": "wireguard",
        "write_enabled": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(deployment, indent=2) + "\n", encoding="utf-8")
    return output


def generate(output: Path, timeout: int, credentials: CloudCredentials | None = None,
             route_mode: str = "site", allowed_ips: list[str] | None = None) -> Path:
    captured, session, sites = discover_sites(timeout, credentials)
    site = _choose("site", sites)
    site_id = str(site.get("id") or site.get("siteId") or "")
    servers = discover_servers(captured, session, site_id)
    server = _choose("WireGuard server", servers)
    return write_deployment(output, captured, session, site, server, credentials,
                            route_mode=route_mode, allowed_ips=allowed_ips)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover an Omada deployment through a secure cloud sign-in")
    parser.add_argument("--output", default="deployment.json")
    parser.add_argument("--timeout", type=int, default=600, help="seconds allowed for sign-in")
    parser.add_argument("--no-store-credentials", action="store_true",
                        help="do not create the encrypted administrator credential file")
    parser.add_argument("--routes", choices=("site", "full", "custom"), default="site",
                        help="traffic routed through the WireGuard tunnel")
    parser.add_argument("--allowed-ips",
                        help="comma-separated networks or individual IPs for --routes custom")
    args = parser.parse_args(argv)
    try:
        credentials = None
        if not args.no_store_credentials:
            print("Enter the Omada Cloud administrator credentials for unattended session renewal.")
            username = input("Omada Cloud login: ").strip()
            password = getpass.getpass("Omada Cloud password: ")
            credentials = CloudCredentials(username, password)
        allowed_ips = _routes(args.routes, args.allowed_ips)
        output = generate(Path(args.output), args.timeout, credentials, args.routes, allowed_ips)
        print(f"Deployment saved to {output}")
        print("Authentication material is encrypted for this Windows user and is not stored in the deployment JSON.")
        return 0
    except EnrollmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
