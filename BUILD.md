# caravel — Build Brief (subagent)

**Read first, in order:** `docs/BUILD.md` → `docs/DESIGN.md` → this file.
This is a delegated subproject. If the design is silent on a contract you need,
stop and raise it — do not invent one. DESIGN §8 and §9 are the core spec for
this app; read them carefully.

---

## What you are building

`caravel` is the PharosVPN mobile client: a native VPN app for Android and iOS.
It does two jobs, in two **decoupled** layers:

1. **VPN engine** — establishes the actual tunnel. Multi-node, multi-protocol.
   It reads only a local profile store and does not care where profiles came from.
2. **Profile sources** — pluggable inputs that populate the local store.

## Architecture decision — shared core + native shells

**v1 approach (validate in C1, then commit):** a **shared core** holding the
profile store, `.pharos` parsing, crypto, and the gRPC sync client; **native
UI** (Jetpack Compose / SwiftUI); **native VPN integration** (`VpnService` on
Android, `NetworkExtension` Packet Tunnel Provider on iOS — these are
platform-mandated, never shared).

Build the shared core as a **Go library** bound via `gomobile`. Rationale: the
`.pharos` format, the envelope crypto, and the gRPC contracts are all already Go
in `coxswain`/`docs/proto` — a Go core means that code is single-sourced, not
reimplemented twice. If C1 finds `gomobile` unworkable, the fallback is Kotlin
Multiplatform; record the decision in this file.

## Profile sources (DESIGN §8)

All sources produce the same artifact — a `.pharos` profile — and drop it into
the local store:

| Source | Implementation note |
|---|---|
| Account sync | gRPC to `relay`→`coxswain`; pull `account`-mode `.pharos`, decrypt with device key |
| QR scan | enrollment ticket (fetch full profile) or self-contained profile QR |
| File import | OS "open with" → `.pharos`; register MIME / UTI / intent filter |
| MDM managed config | Android managed configurations / iOS Managed App Configuration |
| Deep link | `pharosvpn://import?...` |

## `.pharos` handling (DESIGN §9)

- Single extension. Read the header, switch on `enc`: `none` → load; `password`
  → prompt, Argon2id + XChaCha20-Poly1305; `account` → decrypt silently with the
  device's stored private key.
- Content-sniff on `fmt` so renamed files still import.
- Profiles carry a **versioned, tagged protocol list**. Keep a registry of
  protocol handlers keyed by `type`. **Ignore-unknown:** skip a protocol or node
  the engine can't handle; never reject the whole profile.

## Posture (DESIGN §3)

- Detect MDM managed config at launch → *managed* posture: hide account login
  and admin, lock to pushed profiles, honour policy flags in the MDM payload.
- No MDM → *personal* posture: all sources available; show the admin section
  only if the logged-in account has an admin role (small glance-and-quick-actions
  subset — the full console is `coxswain`'s web UI, do not port it).

## Crypto (DESIGN §8)

- Per-user keypair. The private key reaches a new device as a **passphrase-wrapped
  blob** fetched from `coxswain` (Argon2id-derived key unwraps it). It is never sent
  or stored in usable form server-side.
- Store the unwrapped private key in the platform keystore (Android Keystore /
  iOS Keychain, hardware-backed where available).

## Milestones

| # | Output |
|---|---|
| C1 | Skeleton both platforms; validate the shared-core approach; native VPN-permission plumbing |
| C2 | Local profile store + `.pharos` parsing (all `enc` modes) |
| C3 | VPN engine: AmneziaWG tunnel, then XRay; protocol-handler registry |
| C4 | Sources: file import + QR (both kinds) |
| C5 | Account sync: enrollment, gRPC sync, E2E decrypt, multi-device key unwrap |
| C6 | MDM managed config + managed posture; deep links |
| C7 | Role-gated admin subset |

## Non-negotiables

- One app, one store listing. Posture is detected, never a build flag.
- The VPN engine never knows which source a profile came from.
- User private keys live only in the platform keystore, never in app storage.
- Unknown protocols/nodes are skipped, never fatal.

## Depends on

The account/sync protos and the `.pharos` format spec, owned by `coxswain` /
`docs`. Build against `docs/proto/`; do not fork the contracts.
