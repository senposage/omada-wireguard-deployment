from __future__ import annotations

import os
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
    def __init__(self, mappings: Iterable[DriveMapping], *, enabled: bool,
                 provider=None) -> None:
        self.enabled = enabled
        self.expected_suffixes = office_dns_suffixes(mappings)
        self.provider = provider or WindowsDnsSuffixProvider()

    def is_on_office_network(self, tunnel_name: str) -> bool:
        if not self.enabled or not self.expected_suffixes:
            return False
        actual = self.provider.suffixes_except(tunnel_name)
        return bool(self.expected_suffixes.intersection(actual))
