.PHONY: gomobile-install gomobile-bind gomobile-bind-android gomobile-bind-ios clean

# Install gomobile if not present
gomobile-install:
	@command -v gomobile >/dev/null 2>&1 || go install golang.org/x/mobile/cmd/gomobile@latest
	@command -v gobind >/dev/null 2>&1 || go install golang.org/x/mobile/cmd/gobind@latest
	gomobile init

# Build native bindings for both Android and iOS
gomobile-bind: gomobile-bind-android gomobile-bind-ios

# Android binding: generates caravel.aar (Java/Kotlin JNI bindings)
gomobile-bind-android: gomobile-install
	gomobile bind -target=android -o=caravel-android/caravel.aar ./go

# iOS binding: generates caravel.xcframework (Swift/C bindings)
gomobile-bind-ios: gomobile-install
	gomobile bind -target=ios -o=caravel-ios/caravel.xcframework ./go

# Clean build artifacts
clean:
	rm -rf caravel-android/caravel.aar caravel-ios/caravel.xcframework

.PHONY: help
help:
	@echo "Caravel core build targets:"
	@echo "  make gomobile-bind        - Build native bindings (Android + iOS)"
	@echo "  make gomobile-bind-android - Build Android AAR only"
	@echo "  make gomobile-bind-ios     - Build iOS framework only"
	@echo "  make clean                 - Remove build artifacts"
