# C1 Architecture: Final Decision Point

**Date:** 2026-05-31  
**Status:** Gomobile blocker — API level mismatch in NDK setup

---

## What We Found

✅ You have Android NDK installed (30.0.14904198)  
❌ Gomobile can't use it — hits "unsupported API version 16 (not in 21..36)"

**Specific error:** Gomobile sees NDK supports API 21–36, but something is trying to use API 16 (very old, deprecated Android).

**Investigation:** Even your working MyHITV project hits the same error with the current NDK, suggesting:
- NDK 30.0.x may be too new for the gomobile version
- Or gradle/SDK has stale config referencing old APIs
- Or gomobile needs a specific version lock with this NDK

**Time to fix:** Unknown. Could be quick (pinned versions), could be complex (environment cleanup).

---

## Three Paths Forward

### A) **DEBUG GOMOBILE AGGRESSIVELY**
- Pin specific gomobile/NDK versions
- Check for stale Android SDK config (API 16 references)
- Possibly reinstall Android SDK tooling
- **Timeline:** 1–3 hours, _might_ fail and waste the time
- **Payoff:** Gomobile works, single Go core for both platforms

### B) **PIVOT TO KOTLIN MULTIPLATFORM (RECOMMENDED)**
- Rewrite caravel/go/ core in Kotlin (already split into packages)
- Use standard Gradle/Maven (no NDK mystique)
- Android/iOS call Kotlin core (same language, no bindings)
- **Timeline:** 2–3 weeks (not faster, just zero environment surprises)
- **Payoff:** C1 validation proceeds, no NDK/environment issues block you

### C) **MINIMAL GO CORE + NATIVE TUNNEL**
- Keep caravel/go/ thin: just `.pharos` parsing, key unwrap, gRPC client scaffold
- Let Android/iOS implement AmneziaWG tunnel natively (WireGuard FFI)
- More code duplication, avoids gomobile entirely
- **Timeline:** Similar to KMP, skips gomobile but still has Android scaffold work

---

## My Recommendation

**B (KMP).** Here's why:

- Gomobile blocker is environment-specific, not a fundamental issue with the platform
- You have 2–3 weeks for C1 — plenty of time for KMP
- KMP is industry-standard (Slack, DuckDuckGo, Jetbrains) and has zero exotic toolchain
- Core rewrite is mechanical: copy package structure, rewrite Go to Kotlin, link protos
- Less risk of hitting another surprise NDK issue mid-validation

**But it's your call.** If you're confident NDK debugging is quick, go for A. If you want to keep the Go core untouched, go for C (but you'll reimplement tunnel logic).

---

## Next Action

Choose A, B, or C. I'll execute immediately.

