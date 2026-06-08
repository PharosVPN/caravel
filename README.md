<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".assets/logo-inverse.svg">
    <img src=".assets/logo.svg" alt="PharosVPN" width="120" height="120">
  </picture>
</p>
# caravel

> The small, agile ship that crossed unknown oceans.

**`caravel` is the shared PharosVPN client core** (Go) — the engine the platform's
apps are built on. It parses and decrypts profiles, runs account sync, and drives
the VPN tunnel; profiles enter from whichever source fits the user: a synced
account, a QR scan, a file, or enterprise MDM. The per-platform apps
(`caravel-mac` / `-ios` / `-android` / `-linux` and the OpenWRT/OPNsense plugins)
are thin shells over this core.

Part of the [PharosVPN](https://github.com/PharosVPN) platform — see
[`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md).

## Role

- **The VPN client.** Runs the actual tunnel — multi-node, multi-protocol
  (AmneziaWG + XRay/REALITY).
- **Profile sources, not modes.** A VPN engine reads a local profile store;
  profiles enter that store from interchangeable sources — account sync, QR,
  file import, MDM managed config, deep link. "Synced vs unsynced" is just which
  sources are enabled, not a different app.
- **Posture-aware.** *Personal*: account login + QR + file import, with an admin
  section if the logged-in account is an admin. *Managed* (MDM config present):
  account login and admin hidden, profiles locked. **One app, one store listing.**
- **Offline-resilient.** Connects from cached local profiles when the account
  service is unreachable.

## Stack

Go — `CGO_ENABLED=0`, pure-Go AmneziaWG (`amneziawg-go`) + XRay (`xray-core`).
Exposed to the native apps via `gomobile` (`.aar` / `.xcframework`) and consumed
directly by the desktop/router builds. See [BUILD.md](BUILD.md).

## Status

Pre-alpha. The core is shipped and backs the released v0.1.0 clients (macOS,
Linux, Android, plus the OpenWRT/OPNsense plugins and the iOS device build):
`.pharos` parsing/decryption, account sync, and the AmneziaWG + XRay/REALITY
tunnel engine are live. See [BUILD.md](BUILD.md).

## License

Apache-2.0. Contributions under the DCO (`git commit -s`).
