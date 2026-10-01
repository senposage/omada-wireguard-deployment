from __future__ import annotations

import argparse
import json
import sys
import time

from .api import OmadaClient
from .backend import WindowsWireGuardBackend
from .enrollment import EnrollmentService
from .errors import EnrollmentError
from .session import BrowserSessionProvider, CloudCredentialSessionProvider, StoredBrowserSessionProvider
from .settings import DeploymentConfig
from .state import StateStore


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="omada-wg")
    result.add_argument("--config", required=True, help="deployment JSON file")
    sub = result.add_subparsers(dest="command", required=True)
    enroll = sub.add_parser("enroll")
    enroll.add_argument("--name", help="client name; defaults to the computer hostname")
    enroll.add_argument("--no-install", action="store_true", help="resolve/create enrollment without installing WireGuard")
    sub.add_parser("status")
    sub.add_parser("disconnect")
    sub.add_parser("remove-local")
    probe = sub.add_parser("verify-write-cycle", help="create and delete one peer on a test controller")
    probe.add_argument("--name", default=None)
    probe.add_argument("--confirm-test-controller", action="store_true", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = DeploymentConfig.load(args.config)
        display_name = f"Company: {config.site_name} VPN" if config.site_name else "Company VPN"
        backend = WindowsWireGuardBackend(
            installer_dir=config.wireguard_msi_dir, display_name=display_name)
        if args.command == "status":
            print(backend.status(config.tunnel_name))
            return 0
        if args.command == "disconnect":
            backend.stop(config.tunnel_name)
            return 0
        if args.command == "remove-local":
            backend.remove(config.tunnel_name)
            return 0
        if config.credentials_file:
            session = CloudCredentialSessionProvider(str(config.credentials_file), config.user_id or "",
                                                     credential_key=config.credential_key)
        elif config.session_file:
            session = StoredBrowserSessionProvider(str(config.session_file))
        else:
            session = BrowserSessionProvider()
        api = OmadaClient(config, session)
        if args.command == "verify-write-cycle":
            name = args.name or f"omada-wg-probe-{int(time.time())}"
            client_id = api.verify_client_write_cycle(name)
            print(json.dumps({"status": "create-delete-verified", "removed_client_id": client_id}))
            return 0
        service = EnrollmentService(config, api, backend, StateStore(config.state_path))
        state = service.enroll(name=args.name, install=not args.no_install)
        print(json.dumps({"status": "enrolled", "client_id": state.client_id, "client_name": state.client_name}))
        return 0
    except EnrollmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
