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

// TestProfileStoreInterface validates the profile types are exported for gomobile.
func TestProfileStoreInterface(t *testing.T) {
	// Prove the profile package and types are public (gomobile requirement).
	p := &profile.Profile{
		FleetID: "fleet-demo",
		User:    "usr_demo",
		Profiles: []profile.ClientProfile{{
			ID:       "pspec_demo",
			Name:     "demo",
			Protocol: "amneziawg",
			Nodes: []profile.Node{{
				ID:        "nod_demo",
				Name:      "demo",
				Endpoints: []string{"203.0.113.7"},
				Protocols: []profile.Protocol{{Type: "amneziawg", V: 2}},
			}},
		}},
	}
	_ = p
	t.Logf("✓ Profile types exported")
}

// TestSyncClientInterface validates the sync client is exported for gomobile.
func TestSyncClientInterface(t *testing.T) {
	// Prove the sync package surface is exported (gomobile / app use): the
	// high-level Fetch entry point and the lower-level Dial.
	_ = sync.Fetch
	_ = sync.Dial
	t.Logf("✓ Sync client interface exported")
}
