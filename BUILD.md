# caravel — Build Brief (platform split)

**Read first, in order:** `docs/BUILD.md` → `docs/DESIGN.md` (§3, §8) → this file.

This is the **umbrella** project for the PharosVPN mobile client. As of C1 (2026-05-31), the implementation is split into **two platform-specific repos**:

- [`caravel-android`](https://github.com/PharosVPN/caravel-android) — Kotlin + Jetpack Compose
- [`caravel-ios`](https://github.com/PharosVPN/caravel-ios) — Swift + SwiftUI

Both build from a **shared Go core** that lives in this repo.

---

## Architecture: Shared core + native shells

**C1 architecture decision (pending):** 

**Approach:** gomobile (Go compiled to native bindings) + native UI per platform.

```
┌─────────────────────────────────────┐
│  Shared Go core (caravel/go/)       │
│  • VPN engine                       │
│  • Profile store (.pharos)          │
│  • Crypto (Argon2id, XChaCha20)    │
│  • gRPC (account/sync)              │
│  • Protocol handlers (AmneziaWG,    │
│    XRay)                            │
│  • Multi-device key unwrap          │
│  • Compiled via gomobile            │
└─────────────────────────────────────┘
         ↙            ↖
   (native binding) (native binding)
       ↙                   ↖
 ┌──────────────┐    ┌──────────────┐
 │   Android    │    │     iOS      │
 │ (Kotlin UI)  │    │  (Swift UI)  │
 │ Jetpack      │    │  SwiftUI     │
 │ Compose      │    │  Network     │
 │ Android      │    │  Extension   │
 │ Keystore     │    │  Keychain    │
 └──────────────┘    └──────────────┘
```

**Rationale:**
- All platform-agnostic code (crypto, gRPC, tunnel logic) lives once in Go.
- No reimplementation across Kotlin and Swift.
- Proto contracts + codegen are single-sourced from `docs/proto/`.
- gomobile generates native bindings; platform code just calls them.

**If gomobile proves unworkable:** fallback is **Kotlin Multiplatform (KMP)**, where the shared core is written in Kotlin and compiled to both platforms. This is a C1 validation task.

---

## Shared Go core (`caravel/go/`)

The core has no platform dependencies:

- **Tunnel drivers:** AmneziaWG (via coxswain's `internal/wg` package), XRay client (VLESS REALITY).
- **Profile store:** SQLite (via coxswain's sqlite wrapper or `modernc.org/sqlite`); readonly on mobile.
- **Crypto:** Argon2id (key derivation), XChaCha20-Poly1305 (E2E), Ed25519 (signing).
- **gRPC sync client:** reaches coxswain's `AccountSync` service through a beacon relay.
- **Codegen targets:** platform-native bindings (JNI for Android, C bridge for iOS).

**Modules:**
- `vp/` — VPN engine (tunnel setup, peer management, config apply)
- `profile/` — profile store (read `.pharos`, decrypt, apply to tunnel)
- `crypto/` — E2E key handling (Argon2id key unwrap)
- `sync/` — account sync gRPC client
- `proto/` — generated from `docs/proto/` (AccountSync, Notify services, `.pharos` messages)

---

## Profile sources (DESIGN §8)

All sources produce `.pharos` files; the core imports and applies them.

| Source | Responsibility |
|---|---|
| **Account sync** | gRPC call to coxswain (via beacon); decrypt with device key; write to store |
| **QR scan** | enrollment ticket (fetch profile from coxswain) or self-contained profile; write to store |
| **File import** | OS file picker → `.pharos`; validate + write to store |
| **MDM managed config** | pushed profile; write to store (managed posture) |
| **Deep link** | `pharosvpn://import?...` → trigger import flow |

**Platform impl:** each repo (android/ios) handles the UI/permission/file access; calls back into the core to validate + store.

---

## Tunnel engines (DESIGN §3)

The core handles both, selectable by profile.

| Protocol | Transport | Status | Obfuscation |
|---|---|---|---|
| AmneziaWG | UDP 443 | ✅ B2 complete in buoy | Per-node junk, headers, junk templates |
| XRay VLESS+REALITY | TCP 443 | ⚠️ B3 designed, not yet in buoy | TLS spoofing (REALITY) |

**Caravel handling:**
- Read the protocol from the profile.
- Call into the core's tunnel engine to set up.
- Core returns a `net.Conn` abstraction (both protocols wrapped identically).
- Platform VPN integration (NetworkExtension on iOS, VpnService on Android) reads from that conn.

---

## Milestones (C1–C7)

| # | Output | Repo |
|---|---|---|
| C1 | Skeleton both platforms; validate shared-core (gomobile) approach; native VPN integration (permission plumbing, background access) | android + ios |
| C2 | Local profile store + `.pharos` parsing (all `enc` modes: none, password, account) | core + android + ios |
| C3 | VPN engine: AmneziaWG tunnel, then XRay; protocol-handler registry | core + android + ios |
| C4 | Sources: file import + QR (both kinds: ticket + self-contained) | core + android + ios |
| C5 | Account sync: enrollment, gRPC sync, E2E decrypt, multi-device key unwrap | core + android + ios |
| C6 | MDM managed config + managed posture; deep links | android + ios |
| C7 | Role-gated admin subset (for operators running caravel on MDM devices) | android + ios |

---

## Non-negotiables

- **One app, one store listing per platform.** Posture is detected, never a build flag.
- **The VPN engine never knows which source a profile came from.** It just reads `.pharos`.
- **User private keys live only in the platform keystore.** Platform keystore = Android Keystore (hw-backed) / iOS Keychain (Secure Enclave where available). Never in app storage.
- **Unknown protocols/nodes are skipped, not fatal.** If a profile carries an unsupported protocol, caravel silently filters it and offers the supported ones.
- **Shared core is platform-agnostic Go.** No platform-specific code in `caravel/go/`.

---

## Shared code locations

| Path | Shared via |
|---|---|
| `caravel/go/` | source (symlink or submodule from caravel-android / caravel-ios) |
| `caravel/proto/` | codegen (both platforms link to `docs/proto/` or copy) |
| `docs/proto/pharos/account/v1/sync.proto` | contract (authoritative) |
| `docs/proto/pharos/buoy/v1/control.proto` | tunnel config (device keys in this, if multi-hop added) |

---

## Dependencies on other projects

| Project | Milestone | Status | Used by caravel |
|---|---|---|---|
| **coxswain** | M1–M7 | ✅ complete | Account service, profile format, CA (device certs), enrollment API |
| **beacon** | R1–R6 | ✅ complete | Relay to reach coxswain from untrusted networks |
| **buoy** | B1–B2, B4–B5 | ✅ complete (B3 pending) | AmneziaWG data plane; XRay deferred |

---

## Deployment model

### Personal (`caravel init --personal`)

- Single user account (or account disabled).
- No MDM.
- All profile sources available (QR, file, account sync).
- Full admin section if the device account is an admin on coxswain.

### Managed (`caravel init --managed`)

- MDM present (detected at launch).
- Enforced profile source: managed config only.
- Login + account sources hidden.
- Admin section hidden (or read-only metrics only).

---

## Status

🚧 Pre-alpha — C1 architecture decision in progress. Shared core does not yet exist. See [`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md) §3, §8 for the platform design.

---

## See also

- [`caravel-android`](https://github.com/PharosVPN/caravel-android) — Android implementation
- [`caravel-ios`](https://github.com/PharosVPN/caravel-ios) — iOS implementation
- [`docs/BUILD.md`](https://github.com/PharosVPN/docs/blob/main/BUILD.md) — platform-wide roadmap
