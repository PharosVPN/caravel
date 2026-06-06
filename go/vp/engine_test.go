// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package vp

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func b64key(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// TestUAPIRendersObfuscationAndPeer pins the wireguard-go UAPI the engine feeds
// amneziawg-go: hex keys, the interface-level obfuscation params, and the
// server peer with endpoint + allowed-ips.
func TestUAPIRendersObfuscationAndPeer(t *testing.T) {
	cfg := Config{
		PrivateKey:      b64key(t),
		ServerPublicKey: b64key(t),
		PresharedKey:    b64key(t),
		Endpoint:        "203.0.113.7:443",
		Keepalive:       25,
		Obfuscation: Obfuscation{
			Jc: 5, Jmin: 25, Jmax: 800, S1: 20, S2: 30, S3: 40, S4: 50,
			H1: 10, H2: 11, H3: 12, H4: 13,
		},
	}
	uapi, err := cfg.uapi()
	if err != nil {
		t.Fatalf("uapi: %v", err)
	}
	for _, want := range []string{
		"private_key=", "public_key=", "preshared_key=",
		"jc=5", "jmin=25", "jmax=800", "s2=30", "h1=10", "h4=13",
		"endpoint=203.0.113.7:443",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0", "allowed_ip=::/0",
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("UAPI missing %q\n---\n%s", want, uapi)
		}
	}
	// Keys must be hex (64 chars), never the base64 we were handed.
	for _, line := range strings.Split(uapi, "\n") {
		if k, ok := strings.CutPrefix(line, "private_key="); ok {
			if len(k) != 64 {
				t.Errorf("private_key not 64 hex chars: %q", k)
			}
		}
	}
}

// TestTunnelClosedGuards covers the nil-device guards on the Tunnel methods a
// daemon drives concurrently. A zero-value Tunnel models a closed one (dev nil);
// none of these must panic, and Wait must not block. (Bringing a real device up
// needs a tun fd + root, exercised in caravel-opnsense's live VM test.)
func TestTunnelClosedGuards(t *testing.T) {
	var tn Tunnel // dev == nil

	if rx, tx, ok := tn.Stats(); ok || rx != 0 || tx != 0 {
		t.Errorf("Stats on closed tunnel = (%d,%d,%v), want (0,0,false)", rx, tx, ok)
	}
	tn.IpcHandle(nil) // must be a no-op, not a nil deref

	select {
	case <-tn.Wait(): // closed tunnel: channel is already closed
	default:
		t.Error("Wait on a closed tunnel did not return a closed channel")
	}

	if err := tn.Close(); err != nil { // idempotent
		t.Errorf("Close: %v", err)
	}
	if err := tn.Close(); err != nil {
		t.Errorf("double Close: %v", err)
	}
}

func TestUAPIRejectsBadKey(t *testing.T) {
	if _, err := (Config{PrivateKey: "not-base64!!", ServerPublicKey: b64key(t)}).uapi(); err == nil {
		t.Error("expected error on a malformed private key")
	}
	// A valid base64 string of the wrong length is rejected too.
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	if _, err := (Config{PrivateKey: short, ServerPublicKey: b64key(t)}).uapi(); err == nil {
		t.Error("expected error on a 32-byte-key length check")
	}
}
