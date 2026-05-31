#!/bin/bash
# Use NDK 26 (compatible with current gomobile version)
export ANDROID_SDK_ROOT=/Users/khalefa/Library/Android/sdk
export ANDROID_NDK_HOME=/Users/khalefa/Library/Android/sdk/ndk/26.3.11410854
export PATH="$(go env GOPATH)/bin:$PATH"

echo "Using NDK: $ANDROID_NDK_HOME"
gomobile "$@"
