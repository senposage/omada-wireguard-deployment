#!/usr/bin/env python3
"""Build a release artifact for a supported platform target.

The build entry point is intentionally Python rather than shell-specific.  Windows
is the only released target today because it creates a Windows EXE; later targets
can use this same command and argument structure.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def run(*command: str) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def version() -> str:
    source = (ROOT / "src" / "omada_wg" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', source)
    if not match:
        raise RuntimeError("Could not determine the release version")
    return match.group(1)


def windows_csc() -> Path:
    windows_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    for framework in ("Framework64", "Framework"):
        candidate = windows_root / "Microsoft.NET" / framework / "v4.0.30319" / "csc.exe"
        if candidate.is_file():
            return candidate
    raise RuntimeError("The .NET Framework C# compiler (csc.exe) was not found")


def build_windows(release_version: str, output_directory: Path) -> Path:
    if os.name != "nt":
        raise RuntimeError("The Windows EXE target must be built on Windows")
    from omada_wg.package_builder import _build_executable

    work_root = ROOT / "work" / f"release-{release_version}"
    runner_directory = work_root / "runner"
    generator_directory = work_root / "generator"
    sfx_directory = work_root / "sfx"
    sfx = sfx_directory / "OmadaDeploymentSfx.exe"
    runner = runner_directory / "Install-Company-VPN.exe"
    generator_name = f"Omada-WireGuard-Deployment-Generator-{release_version}.exe"
    output = output_directory / generator_name
    output_directory.mkdir(parents=True, exist_ok=True)
    runner_directory.mkdir(parents=True, exist_ok=True)
    generator_directory.mkdir(parents=True, exist_ok=True)
    sfx_directory.mkdir(parents=True, exist_ok=True)

    run(
        str(windows_csc()), "/nologo", "/target:winexe",
        f"/out:{sfx}",
        "/r:System.Windows.Forms.dll", "/r:System.IO.Compression.dll",
        "/r:System.IO.Compression.FileSystem.dll",
        str(ROOT / "sfx" / "OmadaDeploymentSfx.cs"),
    )
    _build_executable(ROOT, runner)
    run(
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", generator_name.removesuffix(".exe"),
        "--paths", str(ROOT / "src"),
        "--icon", str(ROOT / "assets" / "omada-vpn-icon.ico"),
        "--add-binary", f"{runner};runner",
        "--add-binary", f"{sfx};sfx",
        "--add-data", f"{ROOT / 'assets' / 'omada-vpn-icon.png'};assets",
        "--distpath", str(generator_directory / "dist"),
        "--workpath", str(generator_directory / "build"),
        "--specpath", str(generator_directory),
        str(ROOT / "setup_entry.py"),
    )
    shutil.copy2(generator_directory / "dist" / generator_name, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Omada WireGuard release artifacts")
    parser.add_argument("--target", choices=("windows",), default="windows")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs")
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    run(sys.executable, "-m", "PyInstaller", "--version")
    if not args.skip_tests:
        run(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v")
    artifact = build_windows(version(), args.output_dir.resolve())
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    print(f"Created {artifact}")
    print(f"SHA256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
