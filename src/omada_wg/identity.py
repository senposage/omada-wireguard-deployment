from __future__ import annotations

import getpass
import os
import re
import socket

from .errors import ConfigurationError


def normalize_client_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]+", "_", value.strip()).strip("_")
    name = re.sub(r"_+", "_", name)
    if not name:
        raise ConfigurationError("The client identity contains no Omada-compatible characters")
    return name[:64].rstrip("_")


def client_name(mode: str, custom_name: str | None = None) -> str:
    computer = socket.gethostname()
    if mode == "computer_user":
        domain = os.environ.get("USERDOMAIN", "").strip()
        normalized_domain = normalize_client_name(domain) if domain else ""
        local_domains = {"", "workgroup", normalize_client_name(computer).casefold()}
        domain_part = "" if normalized_domain.casefold() in local_domains else f"_{normalized_domain}"
        value = f"{computer}{domain_part}_{getpass.getuser()}"
    elif mode == "computer":
        value = computer
    elif mode == "custom":
        if not custom_name:
            raise ConfigurationError("Custom client naming requires client_custom_name")
        value = custom_name
    else:
        raise ConfigurationError(f"Unknown client naming mode: {mode}")
    return normalize_client_name(value)
