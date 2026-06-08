// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package enroll

import "testing"

func TestParseLink(t *testing.T) {
	const (
		relay = "relay.example.net:443"
		token = "Zm9vYmFyLXRva2Vu"
		ca    = "ab12cd34ef56"
	)
	raw := "pharosvpn://enroll?relay=" + relay + "&token=" + token + "&ca=" + ca
	l, err := ParseLink(raw)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Relay != relay {
		t.Errorf("relay: got %q want %q", l.Relay, relay)
	}
	if l.Token != token {
		t.Errorf("token: got %q want %q", l.Token, token)
	}
	if l.CAFingerprint != ca {
		t.Errorf("ca: got %q want %q", l.CAFingerprint, ca)
	}
}

func TestParseLinkURLEncoded(t *testing.T) {
	// A QR-encoded link percent-encodes the host:port colon as %3A and the token's
	// padding-free base64url may contain '-'/'_' which survive verbatim.
	raw := "pharosvpn://enroll?ca=deadbeef&relay=1.2.3.4%3A8443&token=tok-en_value"
	l, err := ParseLink(raw)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Relay != "1.2.3.4:8443" {
		t.Errorf("relay: got %q", l.Relay)
	}
	if l.Token != "tok-en_value" {
		t.Errorf("token: got %q", l.Token)
	}
	if l.CAFingerprint != "deadbeef" {
		t.Errorf("ca: got %q", l.CAFingerprint)
	}
}

func TestParseLinkRejects(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"wrong scheme":  "https://enroll?relay=r&token=t&ca=c",
		"wrong host":    "pharosvpn://login?relay=r&token=t&ca=c",
		"missing relay": "pharosvpn://enroll?token=t&ca=c",
		"missing token": "pharosvpn://enroll?relay=r&ca=c",
		"missing ca":    "pharosvpn://enroll?relay=r&token=t",
		"not a url":     "::::not a url::::",
	}
	for name, raw := range cases {
		if _, err := ParseLink(raw); err == nil {
			t.Errorf("%s: expected an error, got nil for %q", name, raw)
		}
	}
}
