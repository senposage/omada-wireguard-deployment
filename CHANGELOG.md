# Changelog

This project uses [Semantic Versioning](https://semver.org/). Release tags and generated artifacts use the exact release number without a `v` prefix.

## 0.3.0 — 2026-10-18

- Add a per-user tray option, **Connect VPN when I sign in**, which starts the tray and its existing WireGuard service at that user's next sign-in.
- Drive the tray color and status text from the live Windows service state; blue is shown only while the service is `RUNNING`.

## 0.2.9 — 2026-10-16

- Run the single delayed post-connect mapping synchronization independently of the tray window timer, so the configured drives are applied reliably after Windows completes its own reconnect work.

## 0.2.8 — 2026-10-16

- Restore a LAN mapping only when the drive letter is still actively mapped to this deployment's VPN path; a missing or manually changed mapping is a no-op.

## 0.2.7 — 2026-10-16

- Ensure configured VPN drive mappings are created after the tunnel transitions to connected, including when the tray starts first.
- Keep drive operations transition-driven: allow Windows five seconds to complete its own reconnect work, then inspect and change a mapping at most once per state transition.

## 0.2.6 — 2026-10-16

- Make tray drive handling a no-op on disconnect when a deployment has no configured drive mappings.

## 0.2.5 — 2026-10-15

- Make the Deployment Builder DPI-aware and vertically scrollable, with responsive text wrapping and a more polished section/action layout.

## 0.2.4 — 2026-10-15

- Treat absent, redirected, or temporarily unavailable tray shortcut paths as non-fatal during installation, update, repair, and uninstall.

## 0.2.3 — 2026-10-15

- Add an installer-time all-users option: a Public Desktop shortcut and a tray launch for every user at sign-in, backed by the shared WireGuard tunnel service.

## 0.2.2 — 2026-10-08

- Add a dedicated Office LAN DNS suffix setting, independent of drive mapping domains.
- Classify tray connection failures as an offline PC, local tunnel-service failure, an unreachable VPN gateway, or a removed Omada peer when the controller check is available.

## 0.2.1 — 2026-10-02

- Stop the WireGuard tunnel service and confirm that it is stopped before the tray exits.

## 0.2.0 — 2026-10-01

- Keep generated deployment executables after installation.
- Make LAN drive restoration optional without deleting existing remembered or Group Policy mappings.
- Add Windows tray, drive mapping, repair/re-enrollment, and deployment-builder improvements completed since 0.1.0.

## 0.1.0

- Initial Windows Omada WireGuard deployment generator.
