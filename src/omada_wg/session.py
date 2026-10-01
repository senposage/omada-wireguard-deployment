from __future__ import annotations

import os
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from abc import ABC, abstractmethod

from .errors import AuthenticationError
from .secretstore import DpapiSessionStore


class OmadaSessionProvider(ABC):
    @abstractmethod
    def headers(self, *, vpn_request: bool = False) -> dict[str, str]: ...

    def refresh(self) -> bool:
        return False


class BrowserSessionProvider(OmadaSessionProvider):
    """Temporary bridge. Secrets are read from the environment, never config files."""

    def __init__(self, environ: dict[str, str] | None = None):
        env = environ if environ is not None else os.environ
        names = ("OMADA_COOKIE", "OMADA_CSRF_TOKEN", "OMADA_USER_ID")
        missing = [name for name in names if not env.get(name)]
        if missing:
            raise AuthenticationError("Missing session environment variable(s): " + ", ".join(missing))
        self._cookie = env["OMADA_COOKIE"]
        self._csrf = env["OMADA_CSRF_TOKEN"]
        self._user_id = env["OMADA_USER_ID"]

    def headers(self, *, vpn_request: bool = False) -> dict[str, str]:
        headers = {
            "Cookie": self._cookie,
            "csrf-token": self._csrf,
            "user-id": self._user_id,
            "omada-request-source": "web-remote",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://use1-omada-cloud.tplinkcloud.com",
            "Referer": "https://use1-omada-cloud.tplinkcloud.com/",
            "refresh": "manual",
        }
        if vpn_request:
            headers["request-hash"] = "#VPN"
        return headers


class StoredBrowserSessionProvider(OmadaSessionProvider):
    """Loads a browser session protected for the current Windows user by DPAPI."""

    def __init__(self, path: str):
        value = DpapiSessionStore(path).load()
        self._cookie = value["cookie"]
        self._csrf = value["csrf_token"]
        self._user_id = value["user_id"]
        self._origin = value.get("origin", "https://use1-omada-cloud.tplinkcloud.com")

    def headers(self, *, vpn_request: bool = False) -> dict[str, str]:
        headers = {
            "Cookie": self._cookie,
            "csrf-token": self._csrf,
            "user-id": self._user_id,
            "omada-request-source": "web-remote",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self._origin,
            "Referer": self._origin + "/",
            "refresh": "manual",
        }
        if vpn_request:
            headers["request-hash"] = "#VPN"
        return headers


class CloudCredentialSessionProvider(OmadaSessionProvider):
    """Acquire disposable Omada Cloud session state from stored credentials."""

    cloud_origin = "https://use1-omada-cloud.tplinkcloud.com"
    cloud_manager_api = "https://use1-api-omada-cloud-manager.tplinkcloud.com"
    identity_api = "https://h2api-id.tplinkcloud.com/api/v1"

    def __init__(self, credentials_path: str | None, user_id: str = "", *, credential_key: str | None = None,
                 credentials=None, timeout: float = 30):
        from .credentials import CredentialStore, PortableCredentialStore

        if credentials is not None:
            self._credentials = credentials
        elif credential_key:
            key = PortableCredentialStore.decode_key(credential_key)
            self._credentials = PortableCredentialStore(credentials_path or "", key).load()
        else:
            self._credentials = CredentialStore(credentials_path or "").load()
        self._user_id = user_id
        self._timeout = timeout
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._cookie_jar))
        self._csrf = ""

    @staticmethod
    def _session_code(url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        fragment_query = parsed.fragment.partition("?")[2]
        values = urllib.parse.parse_qs(fragment_query or parsed.query)
        code = (values.get("session_code") or [""])[0]
        if not code:
            raise AuthenticationError("TP-Link login redirect did not contain a session_code")
        return code

    @staticmethod
    def _result(envelope: dict) -> dict:
        code = envelope.get("errorCode", envelope.get("code"))
        if code not in (0, None):
            raise AuthenticationError(envelope.get("msg") or f"TP-Link login failed ({code})")
        result = envelope.get("result", envelope)
        if not isinstance(result, dict):
            raise AuthenticationError("TP-Link login returned an unexpected response")
        return result

    @staticmethod
    def _oauth_code(url: str) -> dict[str, object]:
        """Extract the one-time authorization values returned to Cloud Portal."""
        parsed = urllib.parse.urlsplit(url)
        fragment_query = parsed.fragment.partition("?")[2]
        values = urllib.parse.parse_qs(fragment_query or parsed.query)
        code = (values.get("code") or [""])[0]
        state = (values.get("state") or [""])[0]
        uid_service_url = (values.get("serviceUrl") or values.get("uidServiceUrl") or [""])[0]
        if not code or not state or not uid_service_url:
            raise AuthenticationError(
                "TP-Link authorization redirect did not contain code, state, and serviceUrl"
            )
        canary_value = str((values.get("canary") or ["true"])[0]).casefold()
        return {
            "code": code,
            "state": state,
            "uidServiceUrl": uid_service_url,
            "canary": canary_value != "false",
        }

    def _open_json(self, request: urllib.request.Request) -> dict:
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")
                envelope = json.loads(detail)
                message = envelope.get("msg") or envelope.get("message") or detail
            except (OSError, ValueError, json.JSONDecodeError):
                message = str(exc)
            raise AuthenticationError(f"TP-Link Cloud login request failed: {message}") from exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise AuthenticationError(f"TP-Link Cloud login request failed: {exc}") from exc

    def _login(self) -> None:
        try:
            with self._opener.open(self.cloud_origin, timeout=self._timeout) as response:
                login_url = response.geturl()
        except OSError as exc:
            raise AuthenticationError(f"Cannot start TP-Link Cloud login: {exc}") from exc
        session_code = self._session_code(login_url)
        body = json.dumps({
            "email": self._credentials.username,
            "password": self._credentials.password,
            "terminalUUID": uuid.uuid4().hex,
            "privatePolicyChecked": False,
        }).encode("utf-8")
        request = urllib.request.Request(
            self.identity_api + "/login", data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "session_code": session_code},
        )
        result = self._result(self._open_json(request))
        service_url = str(result.get("serviceUrl", "")).rstrip("/")
        redirect_params = result.get("redirectParams")
        if not service_url or not redirect_params:
            raise AuthenticationError("TP-Link login did not return its authorization redirect")
        query = redirect_params if isinstance(redirect_params, str) else urllib.parse.urlencode(redirect_params)
        try:
            with self._opener.open(service_url + "/oauth/authorize?" + query, timeout=self._timeout) as response:
                authorization = self._oauth_code(response.geturl())
        except OSError as exc:
            raise AuthenticationError(f"TP-Link authorization redirect failed: {exc}") from exc

        exchange_body = json.dumps(authorization).encode("utf-8")
        exchange_request = urllib.request.Request(
            self.cloud_manager_api + "/api/v1/central/account/login-with-uid-code",
            data=exchange_body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Origin": self.cloud_origin,
                "Referer": self.cloud_origin + "/",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        exchange_result = self._result(self._open_json(exchange_request))
        self._csrf = str(exchange_result.get("csrfToken", ""))
        if not self._csrf:
            self._csrf = next((cookie.value for cookie in self._cookie_jar
                               if cookie.name.casefold() == "csrftoken"), "")
        if not self._csrf:
            raise AuthenticationError("TP-Link cloud session exchange completed without a CSRF token")

    def refresh(self) -> bool:
        self._cookie_jar.clear()
        self._csrf = ""
        self._login()
        return True

    def set_user_id(self, user_id: str) -> None:
        if not user_id:
            raise AuthenticationError("Omada Cloud did not return a user ID")
        self._user_id = user_id

    def headers(self, *, vpn_request: bool = False) -> dict[str, str]:
        if not self._user_id:
            raise AuthenticationError("Deployment config is missing user_id")
        if not self._csrf:
            self._login()
        cookie = "; ".join(f"{item.name}={item.value}" for item in self._cookie_jar)
        headers = {
            "Cookie": cookie, "csrf-token": self._csrf, "user-id": self._user_id,
            "omada-request-source": "web-remote", "X-Requested-With": "XMLHttpRequest",
            "Origin": self.cloud_origin, "Referer": self.cloud_origin + "/", "refresh": "manual",
        }
        if vpn_request:
            headers["request-hash"] = "#VPN"
        return headers

    def browser_cookies(self) -> list[dict[str, object]]:
        """Return a Playwright-compatible authenticated Cloud cookie set."""
        if not self._csrf:
            self._login()
        result: list[dict[str, object]] = []
        for cookie in self._cookie_jar:
            item: dict[str, object] = {
                "name": cookie.name, "value": cookie.value,
                "domain": cookie.domain, "path": cookie.path or "/",
                "secure": bool(cookie.secure),
            }
            if cookie.expires:
                item["expires"] = float(cookie.expires)
            result.append(item)
        return result

    def cloud_headers(self, *, user_id: str | None = None) -> dict[str, str]:
        """Headers for Cloud Manager/Access and connector bootstrap calls."""
        if not self._csrf:
            self._login()
        cookie = "; ".join(f"{item.name}={item.value}" for item in self._cookie_jar)
        headers = {
            "Cookie": cookie, "csrf-token": self._csrf,
            "omada-request-source": "web-remote", "X-Requested-With": "XMLHttpRequest",
            "Origin": self.cloud_origin, "Referer": self.cloud_origin + "/", "refresh": "manual",
        }
        effective_user = user_id or self._user_id
        if effective_user:
            headers["user-id"] = effective_user
        return headers
