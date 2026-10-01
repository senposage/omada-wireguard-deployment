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

CLOUD_ORIGIN = "https://use1-omada-cloud.tplinkcloud.com"


class LoginCapture:
    def __init__(self):
        self.candidates: dict[str, dict[str, Any]] = {}
        self.record: dict[str, Any] | None = None
        self.event = threading.Event()

    @staticmethod
    def _looks_like_login(request: Any) -> bool:
        if request.method.upper() != "POST":
            return False
        body = (request.post_data or "").casefold()
        path = urllib.parse.urlsplit(request.url).path.casefold()
        return ("password" in body or '"pwd"' in body or "passwd" in body) and (
            "login" in path or "auth" in path or "account" in path or "sign" in path
        )

    def request(self, request: Any) -> None:
        if not self._looks_like_login(request):
            return
        parsed = urllib.parse.urlsplit(request.url)
        body = request.post_data
        try:
            payload = json.loads(body) if body else None
        except json.JSONDecodeError:
            payload = body
        key = request.url
        self.candidates[key] = {
            "method": request.method.upper(),
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path": parsed.path + (("?" + parsed.query) if parsed.query else ""),
            "request_body": payload,
            "request_content_type": request.headers.get("content-type", ""),
            "response_status": None,
            "response_body": None,
        }

    def response(self, response: Any) -> None:
        record = self.candidates.get(response.url)
        if record is None:
            return
        record["response_status"] = response.status
        try:
            record["response_body"] = response.json()
        except Exception:
            record["response_body"] = "<non-json response>"
        if response.status < 400:
            self.record = record
            self.event.set()


def capture(output: Path, timeout: int) -> Path:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise EnrollmentError("Browser support is not installed. Run: py -m pip install -e .[setup]") from exc
    recorder = LoginCapture()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=False)
        context = browser.new_context()
        context.on("request", recorder.request)
        context.on("response", recorder.response)
        page = context.new_page()
        page.goto(CLOUD_ORIGIN, wait_until="domcontentloaded")
        print("Sign in to Omada Cloud in the opened window.")
        print("The recorder remains open until a successful login request is captured.")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not recorder.event.is_set():
            pages = [candidate for candidate in context.pages if not candidate.is_closed()]
            if not pages:
                raise EnrollmentError("The browser was closed before login capture completed")
            try:
                pages[-1].wait_for_timeout(500)
            except Exception:
                if not any(not candidate.is_closed() for candidate in context.pages):
                    raise EnrollmentError("The browser was closed before login capture completed")
        if recorder.record is None:
            raise EnrollmentError("Timed out without capturing a successful Cloud login request")
        cookies = context.cookies()
        record = dict(recorder.record)
        record["result_cookie_names"] = sorted({cookie["name"] for cookie in cookies})
        output = output.resolve()
        DpapiSessionStore(output).save(record)
        try:
            confirmation = context.pages[-1]
            confirmation.set_content("""
              <!doctype html><html><body style="font-family:Segoe UI;background:#f4f7fb;text-align:center;padding:12vh">
              <main style="background:white;padding:48px;border-radius:16px"><h1 style="color:#16845b">
              Login contract captured</h1><p>The encrypted capture has been saved.</p></main></body></html>
            """)
            confirmation.bring_to_front()
            confirmation.wait_for_timeout(2500)
        except Exception:
            pass
        browser.close()
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture the Omada Cloud login request contract")
    parser.add_argument("--output", default="outputs/omada-cloud-login-contract.dpapi")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    try:
        output = capture(Path(args.output), args.timeout)
        print(f"Encrypted login contract saved to {output}")
        return 0
    except EnrollmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

