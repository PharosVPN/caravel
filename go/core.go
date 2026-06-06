// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package core is the shared VPN engine for caravel (mobile client).
// It exports Go interfaces that gomobile bridges to native code (Kotlin/Swift).
package core

import (
	_ "embed"
	"strings"
)

// versionFile is the caravel version, embedded from VERSION (the single source
// of truth bumped by scripts/bump-version.sh). caravel is a library, so it
// carries its own version rather than taking one via -ldflags.
//
//go:embed VERSION
var versionFile string

// Version returns the caravel core version.
func Version() string {
	return strings.TrimSpace(versionFile)
}

// Config holds the tunnel configuration.
type Config struct {
	Endpoint string
}

// Tunnel is the VPN tunnel interface.
type Tunnel struct {
	config *Config
}

// NewTunnel creates a new tunnel.
func NewTunnel(endpoint string) *Tunnel {
	return &Tunnel{
		config: &Config{Endpoint: endpoint},
	}
}

// Start initializes the tunnel (stub for C1 validation).
func (t *Tunnel) Start() error {
	return nil
}

// Stop tears down the tunnel (stub for C1 validation).
func (t *Tunnel) Stop() error {
	return nil
}
