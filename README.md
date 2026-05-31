# caravel

PharosVPN mobile client — **platform-split architecture**.

> Part of [PharosVPN](https://github.com/PharosVPN) — see [`docs/BUILD.md`](../docs/blob/main/BUILD.md) for the platform roadmap.

## Architecture decision (C1)

**As of 2026-05-31:** The mobile client is split into **two platform-specific repos**:

- **[caravel-android](https://github.com/PharosVPN/caravel-android)** — Kotlin + Jetpack Compose
- **[caravel-ios](https://github.com/PharosVPN/caravel-ios)** — Swift + SwiftUI

Both share a **common Go core** (VPN engine, profile store, gRPC sync, E2E crypto):
- Compiled via `gomobile` to native bindings
- Shared codegen from proto contracts
- Shared test harness

This repo (`PharosVPN/caravel`) serves as the **umbrella**:
- Shared Go core (source of truth for crypto, profile format, gRPC, tunnel engines)
- Shared documentation (BUILD.md, API contracts)
- Platform-specific repos fork from here for their UI implementations

## Milestones

| Milestone | Android | iOS | Status |
|---|---|---|---|
| C1: Skeleton + architecture | [caravel-android](https://github.com/PharosVPN/caravel-android) | [caravel-ios](https://github.com/PharosVPN/caravel-ios) | 🚧 In progress |
| C2: Profile store + `.pharos` | | | Blocked on C1 |
| C3: VPN engines (AmneziaWG, XRay) | | | Blocked on C1 |
| C4: Sources (file, QR) | | | Blocked on C1 |
| C5: Account sync + E2E | | | Blocked on C1 + coxswain M6 |
| C6: MDM + posture | | | Blocked on C1 |
| C7: Admin role subset | | | Blocked on C1 |

## Directory structure (future)

```
caravel/                   (this repo — umbrella / shared core)
├── go/                    (shared Go core — VPN engine, crypto, proto, gRPC)
├── proto/                 (proto contracts, codegen targets)
├── BUILD.md               (shared build brief — see platform docs)
└── LICENSE                (AGPL-3.0-or-later)

caravel-android/           (separate repo)
├── app/                   (Kotlin + Jetpack Compose)
├── go/                    (symlink or git submodule → caravel/go)
└── build.gradle

caravel-ios/               (separate repo)
├── app/                   (Swift + SwiftUI)
├── go/                    (symlink or git submodule → caravel/go)
└── Podfile / Package.swift
```

## Next steps

1. **C1 decision:** Confirm gomobile architecture or switch to Kotlin Multiplatform
2. **Shared core extraction:** Move VPN engine, profile store, crypto, gRPC codegen into `caravel/go/`
3. **Submodule setup:** Each platform repo links `caravel/go` as a git submodule or symlink
4. **Platform scaffolding:** Android and iOS projects link to their native SDKs

## Status

🚧 Pre-alpha — C1 architecture design in progress. See [`docs/DESIGN.md`](../docs/blob/main/DESIGN.md) §3 for the platform design.

## License

AGPL-3.0-or-later. Contributions under the DCO (`git commit -s`).
