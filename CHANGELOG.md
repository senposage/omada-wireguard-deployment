# Changelog

This project uses [Semantic Versioning](https://semver.org/). Release tags and generated artifacts use the exact release number without a `v` prefix.

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
