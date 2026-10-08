# Omada WireGuard Deployment

Windows deployment tooling for Omada Client-to-Site WireGuard. An administrator uses the graphical Deployment Builder to create a site-specific installer; an end user runs that installer to enroll, install, and control a VPN tunnel without using the WireGuard interface.

Current release: **0.2.2**. This is a Windows-only project. macOS is out of scope and Linux is a later follow-up.

## What it does

- Signs in to TP-Link Cloud from the builder, then lets the administrator select a controller, site, and WireGuard server.
- Creates a site-specific, self-contained Windows deployment executable.
- On the client, logs in through TP-Link Cloud, re-discovers the selected controller/site/server, creates or reuses the machine’s WireGuard peer, and installs the official WireGuard for Windows tunnel service.
- Generates the same WireGuard configuration form that Omada exports: a `/32` client address, normalized routes, server public key, endpoint, DNS, and keepalive.
- Installs a site-named tray controller with Connect / Reconnect, Disconnect, status hover text, and a gray disconnected icon.
- Supports automatic start at Windows sign-in, desktop shortcut creation, Windows Installed Apps registration, and clean uninstallation.
- Offers **Update** to reuse an existing peer or **Repair / re-enroll** to delete it and create a fresh one.
- Supports site routes, full tunnel, and custom host/CIDR routes. An individual host is written as a `/32` route.
- Supports optional Windows drive maps while connected, plus optional office-DNS auto-disconnect using a separately configured LAN suffix.

## Administrator workflow

1. Run the **Omada WireGuard Deployment Builder**.
2. Sign in with the Omada Cloud administrator credentials.
3. Select the controller, site, and Client-to-Site WireGuard server.
4. Select the routing policy:
   - **Site networks** — only networks configured at the selected site.
   - **Custom IPs / networks** — only the supplied host IPs or CIDR networks.
   - **Full tunnel** — all internet and site traffic through the VPN.
5. Enter the public gateway / DDNS endpoint and optional DNS, keepalive, or MTU overrides.
6. Optionally configure drive mappings. Each row has a drive letter, VPN/FQDN share, and optional LAN restore share.
   - With a LAN restore share, that path replaces the VPN mapping after disconnect.
   - Without one, the tray restores the mapping Windows already had, when present; otherwise it leaves the drive untouched. It does not delete remembered or Group Policy mappings.
7. Optionally enter the **Office LAN DNS suffix** (for example, `office.example.local`) and enable auto-disconnect. This check is independent of drive mappings, so mapped shares may belong to a different DNS domain.
7. Build the deployment executable, named using the release and site, for example:

   ```text
   Omada-WireGuard-Deployment-0.2.2-Main_Office.exe
   ```

The generated EXE contains the installer engine, an encrypted credential vault, and official signed WireGuard MSIs for x64, ARM64, and x86. It remains available after successful installation so it can be run again for Update or Repair.

## End-user workflow

1. Run the generated site installer and approve Windows elevation.
2. If this computer already has an Omada peer, choose **Update** or **Repair / re-enroll**.
3. Choose whether the tunnel and tray controller should start automatically with Windows.
4. Use the installed tray icon to connect, reconnect, or disconnect. The tray is named after the site and is installed under:

   ```text
   C:\Program Files\Omada WireGuard Deployment
   ```

The installer is registered in Windows Installed Apps as **Company: Site Name VPN (Omada WireGuard)**. Uninstall removes the local service, tray, shortcuts, state, and, when credentials remain available, the Omada peer.

## Credential behavior

The generated installer stores an encrypted Omada Cloud credential vault because it has to establish a fresh remote Cloud session for enrollment, repair, and remote peer removal. Browser session IDs are short-lived and are not packaged.

The builder can optionally delete the installed deployment credentials after the first successful enrollment. In that mode, the local VPN can still be removed, but an Omada peer must be removed manually from the controller later.

Controller-scoped OpenAPI client credentials work through a controller’s direct interface address. They do not currently provide the cloud-connector access required for an off-site installer. The code keeps authentication behind `OmadaSessionProvider` so a future generally available TP-Link account-level Cloud API can replace the Cloud-login provider without changing enrollment logic.

## Development setup

The graphical builder is the supported workflow. Python commands are only for developers working on this repository.

```powershell
py -m pip install -e .[setup,build]
py -m omada_wg.setup_gui
```

Run the test suite with:

```powershell
py -m unittest discover -s tests -v
```

## Build a binary release

The reproducible, cross-platform build entry point is [scripts/build_release.py](scripts/build_release.py). It builds the self-extracting launcher from source, builds the embedded installer engine, runs the test suite, and produces the versioned Deployment Builder EXE.

On a Windows build machine, install Python 3.11+ and the Windows .NET Framework compiler, then run:

```powershell
git clone https://github.com/senposage/omada-wireguard-deployment.git
cd omada-wireguard-deployment
python -m pip install -e ".[setup,build]"
python scripts\build_release.py --target windows
```

The output is written to `outputs\Omada-WireGuard-Deployment-Generator-<version>.exe`. To omit the test run only when it has already been completed separately, use:

```powershell
python scripts\build_release.py --target windows --skip-tests
```

The build command is portable Python. The Windows EXE target itself must run on Windows because it uses Windows resource, C# compiler, and executable-packaging tooling. Future Linux builds will use the same script with a Linux target.

The release builder contains no Omada customer credentials. Site deployment installers are created later by the GUI and should not be committed or attached to a public release because they include the selected deployment configuration and credential vault.

## Test-controller write verification

The WireGuard peer write contract is tested against a dedicated throwaway controller. Do not use this against production.

```powershell
py -m omada_wg.cli --config deployment.json verify-write-cycle --confirm-test-controller
```

It creates one uniquely named throwaway peer and removes it immediately. The command refuses to run unless `write_enabled` is set in the test configuration.

## Release versioning

Releases use Semantic Versioning. The version in `src/omada_wg/__init__.py` is the single source of truth for package metadata and generated artifact names. Git tags and generated filenames use the exact number, such as `0.2.1`, without a `v` prefix. See [CHANGELOG.md](CHANGELOG.md).
