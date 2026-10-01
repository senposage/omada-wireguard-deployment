# Omada WireGuard Auto-Enroller

Windows-first, idempotent enrollment into an Omada Client-to-Site WireGuard server.

## Current milestone

- Uses the confirmed cloud server list/detail endpoints.
- Detects a saved or uniquely named stale machine/user peer and replaces it only after a new tunnel has connected successfully.
- Reproduces Omada-style WireGuard config generation, including `/32` client addresses and normalized routes.
- Installs and starts a native WireGuard for Windows tunnel service.
- Keeps the tunnel configuration under `%ProgramData%\OmadaWireGuard`, grants local users read-only access for inspection, and verifies a real WireGuard handshake before reporting success.
- Installs a site-named tray controller with **Connect / Reconnect**, **Disconnect**, status, and exit actions; users never need to open WireGuard's UI. The icon is full color while connected and gray otherwise, and hovering shows the current connection state.
- Supports optional per-deployment Windows drive maps. On VPN connection the tray saves and replaces any conflicting drive letter (for example local `Z:` → `\\NAS\Shared` with remote `Z:` → `\\nas.example.com\Shared`), then restores the user's previous mapping on disconnect.
- Rediscovers controller, site, server, user, WAN endpoint, and LAN routes on every installer run.
- Rolls back a newly created peer and partial tunnel when enrollment fails.
- Registers a Windows uninstaller that unenrolls the machine from Omada.
- Keeps authentication behind `OmadaSessionProvider`.
- Never writes session secrets or private keys to logs or enrollment state.

The Client-to-Site create/delete contract and WAN endpoint resolution have been verified against the test controller. Generated deployment packages explicitly enable peer creation.

macOS is intentionally out of scope. Linux is planned after the Windows milestone.

Linux drive-mapping follow-up: Linux deployment entries should accept the network share path by itself, such as `\\share\name\folder`, with no Windows drive letter. The Linux mount location and connect/disconnect lifecycle will be implemented with the later Linux backend.

## Setup

Install Python 3.11+ and WireGuard for Windows, then:

```powershell
py -m pip install -e .[setup]
py -m omada_wg.setup_gui
```

The Windows generator GUI collects the Cloud administrator login, site, WireGuard server, public gateway or DDNS override, DNS, routing policy, custom routed IPs/networks, keepalive, MTU, tunnel name, and client naming policy. Its default Omada client identity is domain-aware: `COMPUTER_user` for a local account and `COMPUTER_DOMAIN_user` for a domain account. Characters Omada rejects, including hyphens and backslashes, become underscores. Administrators can save and reload generator configurations; passwords are intentionally requested again when a saved configuration is loaded.

Routing can be selected while generating the deployment:

```powershell
# Route only selected networks/hosts through WireGuard
py -m omada_wg.setup_browser --output deployment.json --routes custom --allowed-ips "192.168.1.50,10.20.30.0/24"

# Route all IPv4 and IPv6 traffic through WireGuard
py -m omada_wg.setup_browser --output deployment.json --routes full
```

An individual custom IPv4 address is written as a `/32` host route. CIDR inputs are normalized before being written to `AllowedIPs`.

The setup GUI authenticates directly with TP-Link Cloud and does not open or automate a browser. It queries Cloud Manager for the Cloud Access host, lists controllers and sites, lists WireGuard servers, and resolves the selected WAN address. Its output is one self-extracting Windows EXE. Operational IDs and sessions are not stored in the deployment; the installer logs in and rediscovers them by the selected names each time.

To capture the exact Cloud login request needed by the automatic session provider:

```powershell
py -m omada_wg.capture_login
```

Set `endpoint_fallback` and `dns` in the generated file. Then run from an elevated terminal:

```powershell
omada-wg --config deployment.json enroll
omada-wg --config deployment.json status
omada-wg --config deployment.json disconnect
omada-wg --config deployment.json remove-local
```

Use `enroll --name NAME` to override the hostname. `--no-install` exercises enrollment without changing the local WireGuard service.

The credential-backed provider performs a fresh TP-Link Cloud login when needed and retries once after Omada returns `-1200`. The encrypted browser-session provider remains available for diagnostics and bootstrap captures.

## One-click Windows package

Run the compiled generator and click **Generate deployment**. It outputs one executable:

```text
Omada-WireGuard-Deployment-Main_Office.exe
```

The selected site name is sanitized and appended to the generated filename. The executable contains the installer engine, encrypted portable credential vault, and official WireGuard MSIs for x64, ARM64, and x86. The generator downloads the current MSIs from WireGuard's official service and requires valid Authenticode signatures. On the client, the executable elevates once, extracts to a temporary directory, installs the architecture-matched WireGuard MSI when necessary, creates or transactionally replaces the Omada peer, installs the tunnel service, connects it, removes temporary files, and deletes the original launcher after success.

The completion screen lets the user choose whether the tunnel service and tray controller start automatically with Windows. The installed controller has a site-specific name such as `Main-Office-VPN-Tray.exe` under `C:\Program Files\Omada WireGuard Deployment`, and Windows starts it at sign-in through the machine Run key. The tray and desktop shortcut use the selected site, such as **Company: Main Office VPN**, and its right-click menu exposes **Connect / Reconnect** and **Disconnect** directly. The installer grants interactive users start/stop rights on this tunnel service only and verifies that Windows retained those permissions. Service commands run without flashing a console window. An administrator can still stop `WireGuardTunnel$omada` in Windows Services or run `omada-wg --config deployment.json disconnect`.

The generator's optional **Drive mappings** field accepts semicolon-separated entries such as `Z:=\\nas.example.com\Shared; S:=\\nas.example.com\Scans`. These mappings run in the signed-in user's session. Existing mappings, including persistent short-name mappings used on the local LAN, are recorded before replacement and restored when the VPN stops. Mapping state is saved under `%LOCALAPPDATA%\OmadaWireGuard` so restoration can recover after a tray restart.

If **Disconnect VPN when the office DNS suffix is present** is selected, the tray derives the DNS suffix from an FQDN share host and checks it only on non-WireGuard adapters every 15 seconds. For example, `Z:=\\DRK-NAS9B372E.dimlaw.local\shared` derives and checks `dimlaw.local`. A match stops the VPN; the existing drive-map restore flow then restores any local short-name mapping. This option requires at least one FQDN drive mapping and never uses a CIDR or gateway MAC.

New Omada peers leave the controller-side Allowed Address override unset so peer routes cannot overlap. Site or custom routes are written into the local client configuration. On a failed first enrollment, the new peer and partial tunnel are rolled back. On rerun, a temporary replacement peer is created and connected first; the stale same-machine/user peer is removed in the same controller update that assigns the final name. A successful install registers **Company: Site Name VPN (Omada WireGuard)** in Windows Installed Apps; uninstalling removes the Omada peer, tunnel service, tray shortcuts, local state, and installed enrollment files.

## Dummy-controller write capture

Do not enable this against production. The captured Omada contract uses a server-level PATCH: the browser generates the WireGuard keypair, selects the first free address in the server pool, appends the client to the full server payload, and commits it with the outer Apply action. The client reproduces that behavior behind `write_enabled`.

The capture helper reuses the Windows-encrypted browser session and saves the observed request/response encrypted as well:

```powershell
py -m omada_wg.capture_contract --config outputs\deployment.json
```

In the opened browser, navigate to the selected WireGuard server and add exactly one throwaway client named `codexcontractprobe`. Confirm the client dialog and then use the server page's outer Apply button. No headers, cookies, or tokens are included in the capture record.

Once that captured template is present, the guarded verification command creates one uniquely named client and removes it immediately:

```powershell
py -m omada_wg.cli --config deployment.json verify-write-cycle --confirm-test-controller
```

It refuses to run unless `write_enabled` is true. If creation succeeds but cleanup fails, it prints the created client ID for manual cleanup.

## Tests

```powershell
py -m unittest discover -s tests -v
```
