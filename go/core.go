// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package core is the shared VPN engine for caravel (mobile client).
// It exports Go interfaces that gomobile bridges to native code (Kotlin/Swift).
package core

//go:generate gomobile init -help

// This package is a gomobile bind target. Build it via:
//   gomobile bind -target=android,ios ./go
//
// This generates:
//   - Android: .aar with Java/Kotlin bindings
//   - iOS: .xcframework with Swift bindings
