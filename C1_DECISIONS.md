# Caravel C1 — Architecture & Decisions

## Stack choice: gomobile + native shells — **LOCKED (toolchain validated 2026-05-31)**

**Chosen:** gomobile (Go → native JNI/C bindings) + Kotlin + Swift

**Rationale:**
1. All platform-agnostic code (crypto, gRPC, tunneling) lives in Go — single source of truth.
   This is **audit-critical**: a VPN core goes through repeated security audits, and one
   Go implementation means auditors review one tunnel, one crypto path, one parser — not two
   divergent reimplementations.
2. Proto contracts (`pharos.account.v1`, `pharos.buoy.v1`) are code-generated to Go; gomobile exposes them to Kotlin/Swift
3. Native UI per platform (Jetpack Compose for Android, SwiftUI for iOS) — each platform gets native UX
4. Proven approach: Tailscale, WireGuard, Signal, **AmneziaWG** all ship gomobile mobile clients

**Decision is final — no KMP fallback.** A Kotlin rewrite would force the crypto and tunnel
logic to be written and audited twice; that is the opposite of what a VPN core needs. The
gomobile toolchain is validated below.

## Validation results (C1 Phase 1 gate — PASSED)

| Metric | Result |
|---|---|
| Android `.aar` builds | ✅ 6.1 MB, all 4 ABIs (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`) |
| iOS `.xcframework` builds | ✅ 14 MB, `ios-arm64` device + `ios-arm64_x86_64-simulator` |
| Warm rebuild time | ✅ ~2 s Android / ~5 s iOS (after first stdlib compile) |
| Reproducible build | ✅ `./build-bindings.sh [android\|ios\|all]` |

### Two setup gotchas (documented so they never bite again)
1. **`-androidapi 24` is mandatory.** NDK r23+ dropped support for API < 21, but gomobile
   defaults to API 16 → `unsupported API version 16 (not in 21..36)`. The fix is the
   `-androidapi` flag (= minSdk floor, **not** an old NDK or old build). `build-bindings.sh`
   sets it to 24 (Android 7.0, ~97% device coverage).
2. **Bind from inside the Go module.** The bind target `go/` is its own module
   (`github.com/PharosVPN/caravel/core`). Running `gomobile bind ./go` from a parent that also
   had a `go.mod` produced `no exported names in the package`. Fix: the umbrella has no root
   `go.mod`; the script does `cd go && gomobile bind … .`

---

## Module structure

```
caravel/                   (umbrella + shared core)
├── go/                    (gomobile bind target)
│   ├── vp/               (VPN engine: AmneziaWG, XRay)
│   ├── profile/          (Profile store: .pharos parsing, SQLite)
│   ├── crypto/           (E2E key unwrap: Argon2id, XChaCha20)
│   ├── sync/             (gRPC AccountSync client)
│   └── proto/            (codegen from docs/proto/)
├── caravel-android/       (separate repo)
│   └── app/              (Kotlin + Jetpack Compose)
└── caravel-ios/           (separate repo)
    └── app/              (Swift + SwiftUI)
```

---

## Gomobile binding flow

```
caravel/go/  ─────────────────────────────────────────────────────────┐
             (package core with exported interfaces: Tunnel, Profile,   │
              Client, etc.)                                             │
                           │                                            │
                           ├─ gomobile bind -target=android ──→  JNI  │
                           │                                      Bindings
                           └─ gomobile bind -target=ios ────→  C Bridge│
                                                                 Bindings│
                                                                        │
                    caravel-android/app/              caravel-ios/app/│
                    ├─ Kotlin code calls JNI   ←──────→  Swift code   │
                    │  interfaces (e.g.                  calls C APIs  │
                    │  core.Tunnel, core.Profile)    (e.g. Tunnel,  │
                    └─ Jetpack Compose UI              Profile)       │
                                                    ├─ SwiftUI UI     │
```

---

## VPN service integration

### Android
- **VpnService** listens for tunnel setup requests
- Calls `core.Dial(config)` → returns tunnel conn
- Reads plaintext from VpnService, writes encrypted to tunnel
- Inverse on RX path

### iOS
- **PacketTunnelProvider** (Network Extension) handles tunnel setup
- Calls `core.Dial(config)` → returns tunnel conn
- NEPacketTunnelProvider reads packets, writes to tunnel
- Reads tunnel output, feeds to PacketTunnelProvider

---

## Communication between platform UI and core

### Kotlin example
```kotlin
// Import JNI bindings from caravel.aar
import core.Core
import core.VpTunnelConfig

// Create tunnel config
val config = VpTunnelConfig()
config.protocol = "amneziawg"
config.endpoint = "vpn.example.com:443"

// Dial
val tunnel = Core.vpDial(config)

// Use tunnel in VpnService
```

### Swift example
```swift
// Import C bridge from caravel.xcframework
import Caravel

// Create tunnel config
let config = GoVpTunnelConfig()
config.protocol_ = "amneziawg"
config.endpoint = "vpn.example.com:443"

// Dial
let tunnel = GoVpDial(config)

// Use tunnel in PacketTunnelProvider
```

---

## Dependencies & unblocked work

| Depends on | Status | Unblocked? |
|---|---|---|
| coxswain M1–M7 | ✅ | Yes — caravel doesn't need it for C1–C3 (local-only tunnel) |
| beacon R1–R6 | ✅ | Yes — needed for C5 (account sync), not C1–C4 |
| buoy B1–B5 | ✅ | Yes — caravel doesn't need buoy binary for C1–C3 |
| Node cascade (decision 18) | ⚠️ designed | No — post-C5 feature, not needed for v1 |

**Bottom line:** C1 is fully unblocked. No external dependencies.

---

## Acceptance criteria (end of C1, 2 weeks)

- [x] `./build-bindings.sh` succeeds for both platforms (Phase 1 — DONE)
- [x] Architecture decision locked: **gomobile** (no KMP fallback)
- [ ] caravel-android app skeleton builds & runs on emulator (Phase 2)
- [ ] caravel-ios app skeleton builds & runs on simulator (Phase 3)
- [ ] Kotlin code can instantiate and call core.Tunnel, core.Profile
- [ ] Swift code can instantiate and call core C APIs
- [ ] VpnService + PacketTunnelProvider integrate without crashes

---

## Known unknowns (to validate in C1)

1. **Gomobile startup overhead** — does the Go runtime add significant latency to app launch?
2. **Gomobile error propagation** — how do Go panics surface to Kotlin/Swift? Do we need a bridge?
3. **Gomobile concurrency** — can we safely run tunnel event loops from goroutines while Kotlin/Swift awaits results?
4. **Keystore/Keychain integration** — can Go crypto code safely receive wrapped keys from platform keystores?

(These are not blockers; they're questions C1 will answer via prototyping.)

---

## Timeline

| Phase | Timeline | Gate | Status |
|---|---|---|---|
| P1: gomobile validation | Week 1 | Binaries build, sane size/time | ✅ DONE |
| P2: Android skeleton | Week 2 | App builds, VpnService integrates | ⬜ next |
| P3: iOS skeleton | Week 2 (parallel with P2) | App builds, PacketTunnelProvider integrates | ⬜ next |
| **C1 gates C2+** | End of week 2 | Architecture locked (gomobile) | ✅ locked |

