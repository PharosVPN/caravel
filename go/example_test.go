// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package core

import (
	"testing"

	"github.com/PharosVPN/caravel/core/profile"
	"github.com/PharosVPN/caravel/core/sync"
	"github.com/PharosVPN/caravel/core/vp"
)

// TestVPNEngineInterface validates the tunnel engine's config surface is
// exported (used by caravel-mac and, via the core, by the mobile shells).
func TestVPNEngineInterface(t *testing.T) {
	cfg := vp.Config{
		Endpoint:        "vpn.example.com:443",
		ServerPublicKey: "test-key",
		AllowedIPs:      []string{"0.0.0.0/0"},
	}
	_ = cfg
	t.Logf("✓ VPN engine config exported")
}

// TestProfileStoreInterface validates the store interface is exported for gomobile.
func TestProfileStoreInterface(t *testing.T) {
	// Prove the profile package and types are public (gomobile requirement)
	p := &profile.Profile{
		EntryEndpoint: "vpn.example.com:443",
		EntryKey:      "test-key",
		Protocols:     []string{"amneziawg"},
	}
	_ = p
	t.Logf("✓ Profile store interface exported")
}

// TestSyncClientInterface validates the sync client is exported for gomobile.
func TestSyncClientInterface(t *testing.T) {
	client := sync.NewClient("beacon.example.com:443")
	_ = client
	t.Logf("✓ Sync client interface exported")
}
