// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package core is the shared VPN engine for caravel (mobile client).
// It exports Go interfaces that gomobile bridges to native code (Kotlin/Swift).
package core

// Version returns the caravel core version.
func Version() string {
	return "0.1.0-c1"
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
