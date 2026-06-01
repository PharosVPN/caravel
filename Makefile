.PHONY: bindings android ios test clean help

# The bindings are built by build-bindings.sh (single source of truth — it sets
# the NDK, the -androidapi floor, and binds from inside the go/ module). Output
# lands in dist/. The Android (caravel-android) and iOS (caravel-ios) apps are
# SEPARATE repos that consume dist/caravel.aar and dist/Caravel.xcframework.

bindings:        ## Build both platform bindings into dist/
	./build-bindings.sh all

android:         ## Build dist/caravel.aar
	./build-bindings.sh android

ios:             ## Build dist/Caravel.xcframework
	./build-bindings.sh ios

test:            ## Test the core Go module
	cd go && go test ./...

clean:           ## Remove built bindings
	rm -rf dist

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'
