#!/usr/bin/env bash
# Build the caravel shared core (go/) into platform bindings via gomobile.
# Artifacts are rebuildable, so they are NOT committed (see .gitignore).
# Run once after cloning and whenever go/ changes.
#
#   ./build-bindings.sh            # both platforms
#   ./build-bindings.sh android    # Android .aar only
#   ./build-bindings.sh ios        # iOS .xcframework only
#
# Outputs:
#   dist/caravel.aar         (copy into the caravel-android app's Gradle libs)
#   dist/Caravel.xcframework (link from the caravel-ios app's Xcode project)
#
# This repo is the CORE library only. The Android (caravel-android) and iOS
# (caravel-ios) apps are SEPARATE repos that consume these artifacts.
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
CORE="$REPO/go"                       # the self-contained Go module (bind target)
ANDROID_API=24                        # minSdk floor — Android 7.0; covers ~97% of devices.
                                      # NOTE: this is the MINIMUM supported API, not the
                                      # build/NDK version. The NDK used is the latest installed.

TARGET="${1:-all}"

# --- toolchain: latest installed NDK, Android Studio's bundled JDK ---
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export ANDROID_HOME
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  export ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
if [ -z "${JAVA_HOME:-}" ] && [ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
export PATH="$PATH:$(go env GOPATH)/bin:${JAVA_HOME:-}/bin"

command -v gomobile >/dev/null 2>&1 || {
  echo "installing gomobile…"
  go install golang.org/x/mobile/cmd/gomobile@latest
  go install golang.org/x/mobile/cmd/gobind@latest
}

echo "SDK=$ANDROID_HOME"
echo "NDK=$ANDROID_NDK_HOME   (latest installed)"
echo "JDK=$(java -version 2>&1 | head -1)"

build_android() {
  mkdir -p "$REPO/dist"
  echo "→ Android .aar (minSdk $ANDROID_API, first run compiles the Android stdlib)…"
  ( cd "$CORE" && gomobile bind -target=android -androidapi "$ANDROID_API" \
      -o "$REPO/dist/caravel.aar" . )
  echo "  done: dist/caravel.aar ($(ls -lh "$REPO/dist/caravel.aar" | awk '{print $5}')) — copy into the caravel-android app's libs"
}

build_ios() {
  mkdir -p "$REPO/dist"
  echo "→ iOS .xcframework (device + simulator)…"
  ( cd "$CORE" && gomobile bind -target=ios,iossimulator \
      -o "$REPO/dist/Caravel.xcframework" . )
  echo "  done: dist/Caravel.xcframework ($(du -sh "$REPO/dist/Caravel.xcframework" | awk '{print $1}')) — link from the caravel-ios app"
}

case "$TARGET" in
  android) build_android ;;
  ios)     build_ios ;;
  all)     build_android; build_ios ;;
  *) echo "usage: $0 [android|ios|all]"; exit 1 ;;
esac
