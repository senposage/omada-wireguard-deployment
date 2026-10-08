from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterable

from .drive_mapping import DriveMapping


def office_dns_suffixes(mappings: Iterable[DriveMapping]) -> frozenset[str]:
    """Derive candidate office DNS suffixes from FQDN UNC share hosts."""
    suffixes: set[str] = set()
    for mapping in mappings:
        host = mapping.path[2:].split("\\", 1)[0].strip().rstrip(".").casefold()
        if "." in host:
            suffixes.add(host.split(".", 1)[1])
    return frozenset(suffixes)


def normalize_dns_suffix(value: str | None) -> str | None:
    """Normalize an administrator-supplied DNS suffix for office detection."""
    if value is None:
        return None
    suffix = value.strip().rstrip(".").casefold()
    if not suffix:
        return None
    labels = suffix.split(".")
    if len(labels) < 2 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels):
        raise ValueError("Office DNS suffix must look like example.local")
    return suffix


class WindowsDnsSuffixProvider:
    def suffixes_except(self, tunnel_name: str) -> set[str]:
        powershell = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        script = (
            "& { param([string]$Tunnel) Get-DnsClient | "
            "Where-Object { $_.InterfaceAlias -ne $Tunnel -and "
            "$_.InterfaceAlias -notlike '*WireGuard*' -and $_.ConnectionSpecificSuffix } | "
            "ForEach-Object { $_.ConnectionSpecificSuffix } }")
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script, tunnel_name],
            text=True, capture_output=True, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            return set()
        return {line.strip().rstrip(".").casefold()
                for line in result.stdout.splitlines() if line.strip()}


class OfficeDnsDetector:
    def __init__(self, mappings: Iterable[DriveMapping] = (), *, enabled: bool,
                 suffix: str | None = None, provider=None) -> None:
        self.enabled = enabled
        # An explicit suffix is independent of drive mappings.  Keep deriving it
        # from old profiles when the new field was not supplied.
        specified = normalize_dns_suffix(suffix)
        self.expected_suffixes = (frozenset({specified}) if specified
                                  else office_dns_suffixes(mappings))
        self.provider = provider or WindowsDnsSuffixProvider()

    def is_on_office_network(self, tunnel_name: str) -> bool:
        if not self.enabled or not self.expected_suffixes:
            return False
        actual = self.provider.suffixes_except(tunnel_name)
        return bool(self.expected_suffixes.intersection(actual))
