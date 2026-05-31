// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package vp (virtual provider) is the VPN tunnel engine.
// It abstracts over AmneziaWG and XRay, exposing a unified tunnel interface.
package vp

// TunnelConfig is the configuration for a single tunnel.
type TunnelConfig struct {
	// Protocol: "amneziawg" or "xray"
	Protocol string
	// Endpoint: server address to connect to
	Endpoint string
	// PublicKey: server's public key (for key exchange)
	PublicKey string
	// PreSharedKey: optional PSK (AmneziaWG post-quantum hardening)
	PreSharedKey string
}

// Tunnel is a live VPN tunnel.
type Tunnel struct {
	config TunnelConfig
	// runtime state (not exported)
	conn interface{} // net.Conn abstraction
	err  error
}

// Dial opens a new tunnel with the given config.
func Dial(cfg TunnelConfig) (*Tunnel, error) {
	// TODO: dispatch based on cfg.Protocol
	// - AmneziaWG: call awg client setup
	// - XRay: call xray VLESS REALITY client
	return &Tunnel{config: cfg}, nil
}

// Close tears down the tunnel.
func (t *Tunnel) Close() error {
	// TODO: cleanup based on protocol
	return nil
}

// Read from the tunnel (simulates net.Conn interface).
func (t *Tunnel) Read(b []byte) (int, error) {
	// TODO: read from underlying conn
	return 0, nil
}

// Write to the tunnel.
func (t *Tunnel) Write(b []byte) (int, error) {
	// TODO: write to underlying conn
	return 0, nil
}
