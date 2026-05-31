# Caravel C1 — Architecture & Decisions

## Stack choice: gomobile + native shells

**Chosen:** gomobile (Go → native JNI/C bindings) + Kotlin + Swift

**Rationale:**
1. All platform-agnostic code (crypto, gRPC, tunneling) lives in Go — single source of truth
2. Proto contracts (`pharos.account.v1`, `pharos.buoy.v1`) are code-generated to Go; gomobile exposes them to Kotlin/Swift
3. Native UI per platform (Jetpack Compose for Android, SwiftUI for iOS) — each platform gets native UX
4. Proven approach: Tailscale, WireGuard, Signal all use gomobile for mobile VPN clients

**Contingency:** If gomobile shows unacceptable overhead or compile times, pivot to Kotlin Multiplatform (core rewritten in Kotlin, shared across both platforms).

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

- [ ] `make gomobile-bind` succeeds for both platforms
- [ ] caravel-android app skeleton builds & runs on emulator
- [ ] caravel-ios app skeleton builds & runs on simulator
- [ ] Kotlin code can instantiate and call core.Tunnel, core.Profile
- [ ] Swift code can instantiate and call core C APIs
- [ ] VpnService + PacketTunnelProvider integrate without crashes
- [ ] Decision locked: gomobile or KMP for C2+

---

## Known unknowns (to validate in C1)

1. **Gomobile startup overhead** — does the Go runtime add significant latency to app launch?
2. **Gomobile error propagation** — how do Go panics surface to Kotlin/Swift? Do we need a bridge?
3. **Gomobile concurrency** — can we safely run tunnel event loops from goroutines while Kotlin/Swift awaits results?
4. **Keystore/Keychain integration** — can Go crypto code safely receive wrapped keys from platform keystores?

(These are not blockers; they're questions C1 will answer via prototyping.)

---

## Timeline

| Phase | Timeline | Gate |
|---|---|---|
| P1: gomobile validation | Week 1 | Binary size, compile time, no memory leaks |
| P2: Android skeleton | Week 2 | App builds, VpnService integrates |
| P3: iOS skeleton | Week 2 (parallel with P2) | App builds, PacketTunnelProvider integrates |
| **C1 gates C2+** | End of week 2 | Architecture locked (gomobile or KMP) |

