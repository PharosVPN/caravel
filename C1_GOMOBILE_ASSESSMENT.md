# C1 Phase 1 Assessment: Gomobile Status

**Date:** 2026-05-31  
**Status:** ⚠️ BLOCKER FOUND — gomobile setup has version/dependency issues

---

## Issue Encountered

When attempting to build Android AAR:
```
gomobile bind requires golang.org/x/mobile in the current module
go: golang.org/x/mobile@v0.0.0-20240612182957-b282f8860ae7: invalid version: unknown revision
```

**Root cause:** golang.org/x/mobile has a pinned version in the codebase that doesn't resolve in the current Go module ecosystem. This suggests:
1. Gomobile is tightly coupled to specific Go versions
2. The version constraints in `go.mod` are not compatible with the current toolchain
3. Setup requires either: version downgrade, Go update, or rethinking the approach

---

## Assessment

### Gomobile Viability: ❌ QUESTIONABLE

**Pros:**
- Single Go codebase for both platforms
- Proven by Signal, WireGuard, Tailscale

**Cons:**
- Complex toolchain setup (NDK, Xcode, Xcode command-line tools, specific Go version)
- Tight version coupling (breaking changes in golang.org/x/mobile)
- Limited idiomatic support for native UI (Go → JNI / C bridge is thin)
- Not an official Go goal post-1.0 (X repository)
- Each gomobile release can require version coordin nation across build chains

### KMP Viability: ✅ STRONG ALTERNATIVE

**Kotlin Multiplatform:**
- Native Kotlin for both platforms (no language boundary)
- Shared core written in Kotlin (no Go, no bindings needed)
- Standard Gradle build (same as any Android project)
- Mature ecosystem: Compose Multiplatform, KMP libraries
- Clear code-sharing boundaries (multiplatform-common, androidMain, iosMain)

**Drawbacks:**
- Crypto/gRPC rewrite from Go to Kotlin
- Kotlin-side proto codegen (already solved: grpc-kotlin, protobuf-kotlin)
- Learning curve on KMP iOS support (Kotlin-to-Swift interop)

---

## Recommendation

**Pivot to Kotlin Multiplatform for C1.**

**Rationale:**
1. Gomobile setup is hitting version/environment issues that suggest fragility
2. KMP is the industry standard for Android/iOS code sharing (Jetbrains, Slack, DuckDuckGo, Cash App all use it)
3. Core logic (VPN engine, profile store, crypto) is not performance-critical enough to justify Go bindings
4. Kotlin expertise is more transferable than gomobile expertise
5. **Time-to-C1 approval:** KMP is faster to validate (Gradle build, no gomobile toolchain)

---

## KMP C1 Plan (revised)

### Phase 1: KMP skeleton (1 week)
- Create `caravel-core/` as a multiplatform Kotlin library
- `commonMain`: VPN engine stubs, profile store interface, crypto
- `androidMain`: Android-specific wiring
- `iosMain`: iOS-specific wiring (Kotlin-to-Swift bridge)
- Build and link both platforms successfully

### Phase 2: Android shell (1 week)
- Jetpack Compose UI + VpnService
- Call `CaravelCore.dial()` from Kotlin (same package language)

### Phase 3: iOS shell (1 week, parallel)
- SwiftUI + PacketTunnelProvider
- Call Kotlin core via KMP iOS binding

---

## Decision Gate

**Proceed with KMP?** Requires:
- [ ] Confirm Kotlin expertise / willingness to rewrite core in Kotlin
- [ ] Accept gRPC/crypto library selection (grpc-kotlin, protobuf-kotlin, bouncy-castle or tink)
- [ ] Timeline: 2–3 weeks to KMP C1 approval (vs. 2 weeks for gomobile if it worked)

---

## Fallback Plan (if KMP also has issues)

Use a **minimal Go core + native shells** approach:
- Keep caravel/go/ as a thin protocol layer (`.pharos` parsing, key unwrap)
- Let Android/iOS implement tunnel engine natively (AmneziaWG FFI, XRay client lib)
- Pros: native performance, simpler dependencies
- Cons: more code duplication, harder to maintain parity

---

## Next Action

1. **Decide:** KMP or stick with gomobile (with more aggressive version debugging)
2. **If KMP:** Update C1 plan, delete gomobile Makefile, scaffold KMP multiplatform project
3. **If gomobile:** Debug version pins, check Go/NDK/Xcode compatibility


---

## UPDATE: NDK Blocker Found

After fixing the Go version, gomobile now requires:
```
gomobile: no usable NDK in /Users/khalefa/Library/Android/sdk
unsupported API version 16 (not in 21..36)
ndk-bundle/meta/platforms.json: no such file or directory
```

**Root cause:** Android NDK must be installed and configured, with API levels in range 21–36.

This is solvable (you have it working in MyHITV), but it reveals:
1. Gomobile requires the full Android SDK+NDK stack (not just Go)
2. Version coupling extends to NDK API levels
3. Each developer must have identical toolchain (if anyone lacks NDK, they can't build)

**Decision remains:**
- **Option A (KMP):** No NDK required. Standard Gradle handles Android. Much simpler CI/CD.
- **Option B (Gomobile + NDK setup):** Possible, but adds Android toolchain complexity to every developer.

