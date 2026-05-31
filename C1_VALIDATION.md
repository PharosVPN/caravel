# Caravel C1 Architecture Validation Plan

**Milestone:** C1 — Skeleton both platforms; validate gomobile architecture; native VPN integration

**Decision point:** Commit to gomobile + native shells OR pivot to Kotlin Multiplatform

**Timeline:** ~2 weeks

---

## Phase 1: Validate gomobile (1 week)

### Goals
- Prove gomobile can compile our core to Android (JNI) and iOS (C bridge)
- Verify performance and memory overhead are acceptable
- Validate that Kotlin/Swift can call Go code cleanly

### Tasks

1. **Install gomobile**
   ```
   go install golang.org/x/mobile/cmd/gomobile@latest
   gomobile init
   ```

2. **Build Android AAR**
   ```
   make gomobile-bind-android
   ```
   Produces: `caravel-android/caravel.aar` (Java/Kotlin bindings)
   
   Test: Can Kotlin code call `core.VpTunnelConfig()`, `core.ProfileNewStore()`, etc.?

3. **Build iOS framework**
   ```
   make gomobile-bind-ios
   ```
   Produces: `caravel-ios/caravel.xcframework` (Swift/C bindings)
   
   Test: Can Swift code call the same interfaces via C bridge?

4. **Benchmark**
   - Time to compile each platform
   - Binary size (overhead of Go runtime + crypto in APK/IPA)
   - Memory footprint at startup
   - **Gate:** <100MB overhead per platform is acceptable

5. **Fallback decision**
   - If gomobile shows:
     - Unacceptable compile times (>5 min per platform)
     - >200MB binary overhead
     - Significant memory leak or performance issue
   - **Then:** Pivot to Kotlin Multiplatform
     - Rewrite core in Kotlin (code-sharing via multiplatform libs)
     - Android: native Kotlin
     - iOS: Kotlin transpiled to Swift via KMP/iOS support

---

## Phase 2: Android skeleton (1 week)

### Goals
- Jetpack Compose UI skeleton
- Permissions and VPN service integration
- Link to caravel-core AAR

### Tasks

1. **Project setup**
   - Create Android app in caravel-android/app/
   - Gradle build files (build.gradle, settings.gradle)
   - Jetpack Compose base

2. **VPN service integration**
   - `VpnService` for tunnel setup
   - Permissions manifest (INTERNET, CHANGE_NETWORK_STATE, BIND_VPN_SERVICE)
   - Background lifecycle management

3. **Link caravel-core**
   - Add caravel.aar as a build dependency
   - Create a `CoreVPN` Kotlin wrapper class that calls `core.*` interfaces
   - Verify compilation

4. **Minimal UI**
   - Home screen with "Connect" button
   - Button calls `CoreVPN.dial(TunnelConfig)`
   - Logs output (no actual UI yet)

---

## Phase 3: iOS skeleton (1 week)

### Goals
- SwiftUI UI skeleton
- Network Extension integration
- Link to caravel-core xcframework

### Tasks

1. **Project setup**
   - Create iOS app in caravel-ios/app/
   - Xcode project + SPM/CocoaPods
   - SwiftUI base

2. **Network Extension integration**
   - `PacketTunnelProvider` for tunnel setup
   - Entitlements for Network Extension
   - Background lifecycle (always-on VPN)

3. **Link caravel-core**
   - Add caravel.xcframework to app
   - Create a `CoreVPN` Swift wrapper class that calls core C APIs
   - Verify compilation + linking

4. **Minimal UI**
   - Home screen with "Connect" toggle
   - Toggle calls `CoreVPN.dial()`
   - Logs output (no actual UI yet)

---

## Success Criteria

### Gomobile validation (gate to Phase 2–3)
- [ ] Android AAR builds without errors (<5 min)
- [ ] iOS xcframework builds without errors (<5 min)
- [ ] Both binaries link cleanly into native projects
- [ ] Binary overhead <100MB per platform
- [ ] No startup memory leaks observed

### Android C1
- [ ] App builds and runs on emulator
- [ ] VpnService integrates without crashes
- [ ] Kotlin can call `core.VpTunnelConfig()` without panics
- [ ] "Connect" button doesn't crash (even if tunnel doesn't actually form)

### iOS C1
- [ ] App builds and runs on simulator
- [ ] PacketTunnelProvider integrates without crashes
- [ ] Swift can call core C APIs without panics
- [ ] "Connect" toggle doesn't crash

---

## If gomobile fails → Kotlin Multiplatform pivot

**KMP approach:**
- Core rewritten in Kotlin (multiplatform library)
- Shared crypto (kotlinx-crypto), gRPC (grpc-kotlin), protobuf (protobuf-kotlin)
- Android: Kotlin + Jetpack Compose (same as above)
- iOS: Kotlin transpiled to Swift via KMP iOS support + SwiftUI wrapper

**Decision timeline:** By end of week 1 of Phase 1. Communicate early if gomobile is not working.

---

## Next phases (C2–C7) blocked on C1 commit

Once C1 locks the architecture (gomobile or KMP):

- **C2:** Local profile store + `.pharos` parsing (actual implementation of core/)
- **C3:** Tunnel engine wiring (AmneziaWG, then XRay)
- **C4:** Sources (file import, QR code, self-contained QR)
- **C5:** Account sync + E2E decrypt
- **C6–C7:** MDM + admin features

---

## Resources

- [gomobile docs](https://pkg.go.dev/golang.org/x/mobile)
- [Kotlin Multiplatform (fallback)](https://kotlinlang.org/docs/multiplatform.html)
- [VpnService (Android)](https://developer.android.com/reference/android/net/VpnService)
- [PacketTunnelProvider (iOS)](https://developer.apple.com/documentation/networkextension/packettunnelprovider)
