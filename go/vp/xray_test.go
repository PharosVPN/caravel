// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package vp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"
)

// TestXRayClientJSON checks the engine renders a valid xray-core client config
// from an XRayConfig: a loopback SOCKS inbound and a VLESS+REALITY outbound
// carrying the device's identity and the node's camouflage.
func TestXRayClientJSON(t *testing.T) {
	cfg := XRayConfig{
		UUID:       "11111111-1111-1111-1111-111111111111",
		Flow:       "xtls-rprx-vision",
		Endpoint:   "203.0.113.7:443",
		PublicKey:  "reality-pub-key",
		ServerName: "www.microsoft.com",
		ShortID:    "",
		// Fingerprint omitted -> defaults to chrome.
	}
	raw, err := cfg.clientJSON(10808)
	if err != nil {
		t.Fatalf("clientJSON: %v", err)
	}

	var got struct {
		Inbounds []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				VNext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID         string `json:"id"`
						Flow       string `json:"flow"`
						Encryption string `json:"encryption"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
			StreamSettings struct {
				Security string `json:"security"`
				Reality  struct {
					ServerName  string `json:"serverName"`
					Fingerprint string `json:"fingerprint"`
					PublicKey   string `json:"publicKey"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("config is not valid JSON: %v\n%s", err, raw)
	}

	if len(got.Inbounds) != 1 || got.Inbounds[0].Port != 10808 || got.Inbounds[0].Protocol != "socks" {
		t.Fatalf("socks inbound = %+v", got.Inbounds)
	}
	if len(got.Outbounds) != 1 || got.Outbounds[0].Protocol != "vless" {
		t.Fatalf("outbound = %+v", got.Outbounds)
	}
	vn := got.Outbounds[0].Settings.VNext
	if len(vn) != 1 || vn[0].Address != "203.0.113.7" || vn[0].Port != 443 {
		t.Fatalf("vnext = %+v", vn)
	}
	u := vn[0].Users[0]
	if u.ID != cfg.UUID || u.Flow != "xtls-rprx-vision" || u.Encryption != "none" {
		t.Fatalf("user = %+v", u)
	}
	r := got.Outbounds[0].StreamSettings
	if r.Security != "reality" || r.Reality.ServerName != "www.microsoft.com" || r.Reality.PublicKey != "reality-pub-key" {
		t.Fatalf("reality = %+v", r)
	}
	if r.Reality.Fingerprint != defaultXRayFingerprint {
		t.Fatalf("fingerprint = %q, want default %q", r.Reality.Fingerprint, defaultXRayFingerprint)
	}
}

// TestXRayRealityEngine stands up an in-process REALITY server (freedom egress)
// and the engine's xray client, then proves a request through the client's
// SOCKS inbound rides the REALITY tunnel to the server and reaches a target.
// Skipped when the decoy host is unreachable (the REALITY handshake relays to
// it), so airgapped CI doesn't fail.
func TestXRayRealityEngine(t *testing.T) {
	const decoy = "www.microsoft.com"
	if c, err := net.DialTimeout("tcp", decoy+":443", 3*time.Second); err != nil {
		t.Skipf("decoy %s:443 unreachable (%v) — skipping live REALITY test", decoy, err)
	} else {
		c.Close()
	}

	// Local egress target: the server's freedom outbound dials it.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello-through-reality")
	}))
	defer target.Close()

	priv, pub := realityTestKeypair(t)
	const uuid = "22222222-2222-2222-2222-222222222222"
	const flow = "xtls-rprx-vision"

	serverPort := mustPort(t)
	socksPort := mustPort(t)

	serverJSON := fmt.Sprintf(`{
      "inbounds": [{"port": %d, "listen": "127.0.0.1", "protocol": "vless",
        "settings": {"clients": [{"id": %q, "flow": %q}], "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "reality",
          "realitySettings": {"dest": %q, "serverNames": [%q], "privateKey": %q, "shortIds": [""]}}}],
      "outbounds": [{"protocol": "freedom"}]
    }`, serverPort, uuid, flow, decoy+":443", decoy, priv)

	server, err := startXray(serverJSON)
	if err != nil {
		t.Fatalf("start REALITY server: %v", err)
	}
	defer server.Close()

	cfg := XRayConfig{
		UUID:       uuid,
		Flow:       flow,
		Endpoint:   fmt.Sprintf("127.0.0.1:%d", serverPort),
		PublicKey:  pub,
		ServerName: decoy,
	}
	clientJSON, err := cfg.clientJSON(socksPort)
	if err != nil {
		t.Fatalf("clientJSON: %v", err)
	}
	client, err := startXray(clientJSON)
	if err != nil {
		t.Fatalf("start xray client: %v", err)
	}
	defer client.Close()

	time.Sleep(500 * time.Millisecond) // let both instances bind

	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks dialer: %v", err)
	}
	hc := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext},
	}
	resp, err := hc.Get(target.URL)
	if err != nil {
		t.Fatalf("GET through REALITY tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-through-reality" {
		t.Fatalf("body = %q, want hello-through-reality", body)
	}
}

func realityTestKeypair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv), base64.RawURLEncoding.EncodeToString(pub)
}

func mustPort(t *testing.T) int {
	t.Helper()
	p, err := reserveLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
