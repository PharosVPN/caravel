# caravel

> The small, agile ship that crossed unknown oceans.

**`caravel` is the PharosVPN mobile client** — the app end-users actually run.
It establishes the VPN tunnel and acquires its profiles from whichever source
fits the user: a synced account, a QR scan, a file, or enterprise MDM.

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

Native — Kotlin (Android) + Swift (iOS) — over a shared core. See [BUILD.md](BUILD.md).

## Status

🚧 Pre-alpha — scaffolding. See [BUILD.md](BUILD.md).

## License

AGPL-3.0-or-later. Contributions under the DCO (`git commit -s`).
