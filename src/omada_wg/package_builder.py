from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import struct
import sys
import tempfile
import urllib.request
from pathlib import Path

from .errors import ConfigurationError, EnrollmentError
from .bootstrap import resolve_runtime
from .cloud_discovery import CloudDiscoveryClient
from .credentials import PortableCredentialStore
from .settings import DeploymentConfig


WIREGUARD_INDEX = "https://download.wireguard.com/windows-client/"
ARCHITECTURES = ("amd64", "arm64", "x86")
SFX_MAGIC = b"OMADAWGPKG00001"


def _latest_msi(index: str, architecture: str) -> str:
    matches = set(re.findall(rf"wireguard-{re.escape(architecture)}-([0-9.]+)\.msi", index))
    if not matches:
        raise EnrollmentError(f"The official WireGuard download page has no {architecture} MSI")
    version = max(matches, key=lambda value: tuple(int(part) for part in value.split(".")))
    return f"wireguard-{architecture}-{version}.msi"


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "Omada-WireGuard-Deployment-Builder/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    except OSError as exc:
        raise EnrollmentError(f"Cannot download {url}: {exc}") from exc


def _verify_authenticode(path: Path) -> None:
    windows_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    environment = os.environ.copy()
    environment["PSModulePath"] = str(
        windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "Modules")
    command = [
        str(powershell), "-NoProfile", "-NonInteractive", "-Command",
        "& { param([string]$Path) (Get-AuthenticodeSignature -LiteralPath $Path).Status.ToString() }",
        str(path),
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False, env=environment)
    if result.returncode or result.stdout.strip() != "Valid":
        raise EnrollmentError(f"The bundled WireGuard MSI did not have a valid Authenticode signature: {path.name}")


def _build_executable(project: Path, destination: Path) -> None:
    bundled_root = getattr(sys, "_MEIPASS", None)
    if bundled_root:
        bundled = Path(bundled_root) / "runner" / "Install-Company-VPN.exe"
        if not bundled.is_file():
            raise EnrollmentError("The deployment generator is missing its embedded installer engine")
        shutil.copy2(bundled, destination)
        return
    (project / "work").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="omada-wg-build-", dir=project / "work") as temporary:
        root = Path(temporary)
        command = [
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
            "--name", "Install-Company-VPN", "--paths", str(project / "src"),
            "--icon", str(project / "assets" / "omada-vpn-icon.ico"),
            "--add-data", f"{project / 'assets' / 'omada-vpn-icon.png'};assets",
            "--add-data", f"{project / 'assets' / 'omada-vpn-icon.ico'};assets",
            "--add-data", f"{project / 'assets' / 'omada-vpn-icon-disconnected.ico'};assets",
            "--hidden-import", "win32com.client",
            "--hidden-import", "win32api",
            "--hidden-import", "win32con",
            "--hidden-import", "win32event",
            "--hidden-import", "win32gui",
            "--hidden-import", "winerror",
            "--distpath", str(root / "dist"), "--workpath", str(root / "build"),
            "--specpath", str(root), str(project / "deploy_entry.py"),
        ]
        result = subprocess.run(command, cwd=project, text=True, capture_output=True, check=False)
        if result.returncode:
            raise EnrollmentError("Could not build the deployment app:\n" + (result.stderr or result.stdout)[-4000:])
        shutil.copy2(root / "dist" / "Install-Company-VPN.exe", destination)


def _hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS.json"):
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def build(config_path: Path, output_dir: Path, architectures: tuple[str, ...] = ARCHITECTURES) -> Path:
    project = Path(__file__).resolve().parents[2]
    output_dir = output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ConfigurationError(f"Output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        deployment = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Cannot read deployment settings: {exc}") from exc
    if not deployment.get("credentials_file") or not deployment.get("credential_key"):
        raise ConfigurationError("Generate a portable credential vault with the deployment GUI first")
    endpoint = str(deployment.get("endpoint_fallback") or "")
    if not endpoint or endpoint.startswith("REPLACE_"):
        raise ConfigurationError("Set the deployment public gateway or DDNS endpoint first")
    source_credentials = config_path.parent / deployment["credentials_file"]
    if not source_credentials.is_file():
        raise ConfigurationError(f"Credential vault was not found: {source_credentials}")

    key = PortableCredentialStore.decode_key(str(deployment["credential_key"]))
    credentials = PortableCredentialStore(source_credentials, key).load()
    resolved = resolve_runtime(DeploymentConfig.load(config_path), CloudDiscoveryClient(credentials))
    deployment.update({
        "connector_base_url": None,
        "controller_name": resolved.controller_name,
        "device_id": None,
        "omada_id": None,
        "site_id": None,
        "site_name": resolved.site_name,
        "user_id": None,
        "server_id": None,
        "server_name": resolved.server_name,
        "endpoint_fallback": resolved.endpoint_fallback,
        "site_routes": list(resolved.site_routes),
    })

    deployment["write_enabled"] = True
    deployment["session_file"] = None
    deployment["credentials_file"] = "deployment.credentials.bin"
    deployment["wireguard_msi_dir"] = "wireguard"
    deployment["state_path"] = r"%ProgramData%\OmadaWireGuard\enrollment.json"
    (output_dir / "deployment.json").write_text(json.dumps(deployment, indent=2) + "\n", encoding="utf-8")
    shutil.copy2(source_credentials, output_dir / "deployment.credentials.bin")

    msi_dir = output_dir / "wireguard"
    msi_dir.mkdir()
    try:
        with urllib.request.urlopen(WIREGUARD_INDEX, timeout=30) as response:
            index = response.read().decode("utf-8", errors="replace")
    except OSError as exc:
        raise EnrollmentError(f"Cannot read the official WireGuard download page: {exc}") from exc
    for architecture in architectures:
        if architecture not in ARCHITECTURES:
            raise ConfigurationError(f"Unknown Windows architecture: {architecture}")
        filename = _latest_msi(index, architecture)
        target = msi_dir / filename
        _download(WIREGUARD_INDEX + filename, target)
        _verify_authenticode(target)

    _build_executable(project, output_dir / "Install-Company-VPN.exe")
    (output_dir / "SHA256SUMS.json").write_text(json.dumps(_hashes(output_dir), indent=2) + "\n", encoding="utf-8")
    archive = Path(shutil.make_archive(str(output_dir), "zip", output_dir))
    return archive


def build_self_extracting(config_path: Path, output_exe: Path,
                          architectures: tuple[str, ...] = ARCHITECTURES) -> Path:
    project = Path(__file__).resolve().parents[2]
    bundled_root = getattr(sys, "_MEIPASS", None)
    stub = ((Path(bundled_root) / "sfx" / "OmadaDeploymentSfx.exe") if bundled_root
            else (project / "assets" / "OmadaDeploymentSfx.exe"))
    if not stub.is_file():
        raise EnrollmentError("The deployment generator is missing its self-extracting launcher")
    output_exe = output_exe.resolve()
    if output_exe.suffix.casefold() != ".exe":
        output_exe = output_exe.with_suffix(".exe")
    output_exe.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="omada-wg-sfx-") as temporary:
        temporary_root = Path(temporary)
        archive = build(config_path, temporary_root / "payload", architectures)
        candidate = temporary_root / output_exe.name
        with stub.open("rb") as launcher, archive.open("rb") as payload, candidate.open("wb") as target:
            shutil.copyfileobj(launcher, target)
            payload_length = archive.stat().st_size
            shutil.copyfileobj(payload, target)
            target.write(struct.pack("<Q", payload_length))
            target.write(SFX_MAGIC)
        candidate.replace(output_exe)
    return output_exe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a one-click Windows Omada WireGuard deployment")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", default="outputs/Omada-VPN-Deployment")
    parser.add_argument("--architectures", default=",".join(ARCHITECTURES))
    args = parser.parse_args(argv)
    try:
        architectures = tuple(value.strip() for value in args.architectures.split(",") if value.strip())
        archive = build(Path(args.config).resolve(), Path(args.output), architectures)
        print(f"Deployment package created: {archive}")
        return 0
    except EnrollmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
