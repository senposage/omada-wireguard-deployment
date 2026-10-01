from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from .errors import EnrollmentError
from .secretstore import DpapiSessionStore
from .settings import DeploymentConfig


class ContractCapture:
    def __init__(self, marker: str = "codexcontractprobe"):
        self.event = threading.Event()
        self.record: dict[str, Any] | None = None
        self.marker = marker

    @staticmethod
    def _is_vpn_write(url: str, method: str) -> bool:
        path = urllib.parse.urlsplit(url).path.casefold()
        return (method.upper() not in {"GET", "HEAD", "OPTIONS"}
                and "vpn" in path and not path.endswith("/defaultvalue"))

    def request(self, request: Any) -> None:
        if (not self._is_vpn_write(request.url, request.method) or self.record is not None
                or self.marker.casefold() not in (request.post_data or "").casefold()):
            return
        parsed = urllib.parse.urlsplit(request.url)
        post_data = request.post_data
        try:
            payload = json.loads(post_data) if post_data else None
        except json.JSONDecodeError:
            payload = post_data
        self.record = {
            "method": request.method.upper(),
            "path": parsed.path + (("?" + parsed.query) if parsed.query else ""),
            "request_body": payload,
            "response_status": None,
            "response_body": None,
        }
        self.event.set()

    def response(self, response: Any) -> None:
        if self.record is None or not self._is_vpn_write(response.url, response.request.method):
            return
        parsed = urllib.parse.urlsplit(response.url)
        expected_path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        if self.record["path"] != expected_path:
            return
        self.record["response_status"] = response.status
        try:
            self.record["response_body"] = response.json()
        except Exception:
            self.record["response_body"] = "<non-json response>"


def _cookie_objects(cookie_header: str) -> list[dict[str, Any]]:
    result = []
    for part in cookie_header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            result.append({
                "name": name, "value": value, "domain": ".tplinkcloud.com",
                "path": "/", "secure": True, "sameSite": "Lax",
            })
    return result


def capture(config_path: Path, output: Path, timeout: int, client_name: str) -> Path:
    config = DeploymentConfig.load(config_path)
    if not config.session_file:
        raise EnrollmentError("The deployment does not reference an encrypted browser session")
    session = DpapiSessionStore(config.session_file).load()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise EnrollmentError("Browser support is not installed. Run: py -m pip install -e .[setup]") from exc
    recorder = ContractCapture(client_name)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=False)
        context = browser.new_context()
        context.add_cookies(_cookie_objects(session["cookie"]))
        context.on("request", recorder.request)
        context.on("response", recorder.response)
        page = context.new_page()
        page.goto(session.get("origin", "https://use1-omada-cloud.tplinkcloud.com"),
                  wait_until="domcontentloaded")
        print("Open the selected controller and WireGuard server, then add ONE throwaway client.")
        print(f"Required capture name: {client_name}")
        print("The recorder closes immediately after it captures the write request.")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not recorder.event.is_set():
            open_pages = [candidate for candidate in context.pages if not candidate.is_closed()]
            if not open_pages:
                raise EnrollmentError("The setup browser was closed before a matching request was captured")
            try:
                open_pages[-1].wait_for_timeout(500)
            except Exception:
                # TP-Link may close the launcher tab while opening the controller tab.
                if not any(not candidate.is_closed() for candidate in context.pages):
                    raise EnrollmentError("The setup browser was closed before capture completed")
        if not recorder.event.is_set() or recorder.record is None:
            browser.close()
            raise EnrollmentError("Timed out without seeing a WireGuard write request")
        page.wait_for_timeout(1500)
        output = output.resolve()
        DpapiSessionStore(output).save(recorder.record)
        try:
            confirmation = context.pages[-1]
            confirmation.set_content("""
              <!doctype html><html><body style="font-family:Segoe UI;background:#f4f7fb;text-align:center;padding:12vh">
              <main style="background:white;padding:48px;border-radius:16px"><h1 style="color:#16845b">
              Request captured securely</h1><p>You can return to the deployment tool.</p></main></body></html>
            """)
            confirmation.bring_to_front()
            confirmation.wait_for_timeout(2000)
        except Exception:
            pass
        browser.close()
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Securely capture Omada's WireGuard client write contract")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", default="outputs/wireguard-write-contract.dpapi")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--client-name", default="codexcontractprobe")
    args = parser.parse_args(argv)
    try:
        output = capture(Path(args.config), Path(args.output), args.timeout, args.client_name)
        print(f"Encrypted write contract saved to {output}")
        return 0
    except EnrollmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
