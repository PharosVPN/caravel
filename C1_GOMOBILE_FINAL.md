# C1 Architecture: Gomobile Rationale (Final)

**Decision:** Stick with Go + gomobile. Recompile NDK 26 (compatible version).

---

## Why Single Go Core Matters

**Audit-critical:** caravel will go through multiple security audits. A single Go core means:
- ✅ Auditors review one tunnel implementation, one crypto implementation, one profile parser
- ✅ Android and iOS run identical core logic (no reimplementation = no divergence bugs)
- ✅ Battle-tested: WireGuard, Signal, Tailscale all ship gomobile
- ✅ Go's memory safety + type system catch more issues than manual JNI/FFI

**Rewrite in Kotlin would mean:**
- ❌ Two implementations to audit (Go + Kotlin)
- ❌ Crypto: cryptographic code written twice (tink, bouncy-castle in Kotlin; x/crypto in Go)
- ❌ Tunnel logic: AmneziaWG FFI in Android, native in iOS — no single source
- ❌ gRPC contracts coded twice (grpc-kotlin + protobuf-kotlin)
- ❌ Risk of subtle implementation divergence under audit pressure

**Gomobile is the right call for a production VPN.**

---

## Technical Fix

The NDK 30 API 16 error is a version mismatch:
- Gomobile expects NDK to support API 16+ (it does: NDK 30 supports 21–36)
- But gomobile's internal check fails when it can't find API 16 headers
- **Solution:** Use NDK 26.3 (confirmed compatible with current gomobile)

**Action:** Installing NDK 26 in parallel. Once done:
```bash
./gomobile.sh bind -target=android -o=caravel-android/caravel.aar ./go
```

---

## C1 Timeline (Revised)

| Phase | Work | Duration |
|---|---|---|
| **Immediate** | NDK 26 install + test Android AAR build | 30 min |
| **Phase 1 (Week 1)** | Android AAR + iOS xcframework, benchmark build time/binary size | 1 week |
| **Phase 2 (Week 2)** | Android Jetpack Compose + VpnService + caravel.aar link | 1 week |
| **Phase 3 (Week 2, parallel)** | iOS SwiftUI + PacketTunnelProvider + caravel.xcframework link | 1 week |

---

## Gate Decision (after Phase 1)

Build both binaries, measure:
- ✅ Android AAR build time (<5 min acceptable)
- ✅ APK size overhead (<100 MB acceptable)
- ✅ iOS xcframework build time
- ✅ Binary loads without panics
- ✅ No memory leaks on startup

**If all pass:** commit to gomobile, proceed to Phase 2–3.  
**If any fail:** fallback to KMP.

---

## Why We're Not Pivoting

NDK version mismatch ≠ gomobile is broken. It's a build environment issue, solvable in 30 min. The platform itself is proven and worth the short setup cost.

