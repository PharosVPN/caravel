// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package profile

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/PharosVPN/caravel/core/crypto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// sampleProfile is a one-node AmneziaWG profile with an endpoint pool, a /32
// address, and a full obfuscation set — the shape the controller emits.
func sampleProfile(t *testing.T) Profile {
	t.Helper()
	params := AmneziaWG{
		PrivateKey:   "QlpVeFhVc0xkSGRoY21VZ2FYTWdkR2hsSUd4dloyOD0=",
		Address:      "10.86.0.5/32",
		PublicKey:    "U0VWU1JTQkpVeUJVU0VVZ1RFOUhUeUJoYm1RZ2FYUT0=",
		PresharedKey: "VEZWRFMxa2dWMVZUSUVOUFRVVWdRVTVFSUVkUFRFUT0=",
		Endpoints:    []EndpointPool{{IP: "203.0.113.7", PortMin: 51820, PortMax: 51830}},
		AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
		Obfuscation:  Obfuscation{Jc: 5, Jmin: 25, Jmax: 800, S1: 20, S2: 30, S3: 40, S4: 50, H1: 10, H2: 11, H3: 12, H4: 13},
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return Profile{
		FleetID:  "fleet-demo",
		User:     "usr_demo",
		Revision: 7,
		Profiles: []ClientProfile{{
			ID:       "pspec_demo",
			Name:     "Amsterdam Direct",
			Protocol: "amneziawg",
			Nodes: []Node{{
				ID:        "nod_ams1",
				Name:      "Amsterdam-1",
				Region:    "eu-nl",
				Endpoints: []string{"203.0.113.7"},
				Protocols: []Protocol{{Type: "amneziawg", V: 2, Params: raw}},
			}},
		}},
	}
}

func writePlain(t *testing.T, p Profile) []byte {
	t.Helper()
	payload, _ := json.Marshal(p)
	data, err := json.MarshalIndent(envelope{Fmt: formatTag, V: formatVersion, Enc: EncNone, Payload: payload}, "", "  ")
	if err != nil {
		t.Fatalf("write plain: %v", err)
	}
	return data
}

// writePassword mirrors the controller's pharos.WritePassword exactly.
func writePassword(t *testing.T, p Profile, password string) []byte {
	t.Helper()
	plaintext, _ := json.Marshal(p)
	salt := randBytes(t, 16)
	kdf := &kdfParams{Algo: "argon2id", Time: crypto.ArgonTime, Memory: crypto.ArgonMemory, Threads: crypto.ArgonThreads, Salt: salt}
	key := argon2.IDKey([]byte(password), salt, kdf.Time, kdf.Memory, kdf.Threads, crypto.KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	env := envelope{Fmt: formatTag, V: formatVersion, Enc: EncPassword, KDF: kdf, Nonce: randBytes(t, aead.NonceSize())}
	aad, _ := env.aad()
	ct := aead.Seal(nil, env.Nonce, plaintext, aad)
	env.Payload, _ = json.Marshal(ct)
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("write password: %v", err)
	}
	return data
}

// writeAccount mirrors the controller's e2e.Seal + pharos.WrapSealedBundle.
func writeAccount(t *testing.T, p Profile, recipientPub []byte, signer ed25519.PrivateKey) []byte {
	t.Helper()
	plaintext, _ := json.Marshal(p)
	dataKey := randBytes(t, 32)
	payloadAEAD, _ := chacha20poly1305.NewX(dataKey)
	nonce := randBytes(t, payloadAEAD.NonceSize())
	ct := payloadAEAD.Seal(nil, nonce, plaintext, nil)

	ephPriv := randBytes(t, 32)
	ephPub, _ := curve25519.X25519(ephPriv, curve25519.Basepoint)
	shared, _ := curve25519.X25519(ephPriv, recipientPub)
	wrapKey := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte("pharosvpn/profile/keywrap/v1")), wrapKey)
	wrapAEAD, _ := chacha20poly1305.NewX(wrapKey)
	wn := randBytes(t, wrapAEAD.NonceSize())

	b := crypto.SealedBundle{V: 1, EphPublic: ephPub, WrapNonce: wn, WrappedKey: wrapAEAD.Seal(nil, wn, dataKey, nil), Nonce: nonce, Ciphertext: ct}
	unsigned := b
	unsigned.Signature = nil
	signed, _ := json.Marshal(unsigned)
	b.Signature = ed25519.Sign(signer, signed)

	payload, _ := json.Marshal(b)
	data, err := json.MarshalIndent(envelope{Fmt: formatTag, V: formatVersion, Enc: EncAccount, Payload: payload}, "", "  ")
	if err != nil {
		t.Fatalf("write account: %v", err)
	}
	return data
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// assertResolvesToTunnel checks a parsed profile resolves to the expected dial.
func assertResolvesToTunnel(t *testing.T, p *Profile) {
	t.Helper()
	cp, err := p.Select("")
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	node, err := cp.Node("")
	if err != nil {
		t.Fatalf("Node: %v", err)
	}
	tun, err := node.Tunnel()
	if err != nil {
		t.Fatalf("Tunnel: %v", err)
	}
	// The single-IP pool resolves to that IP with a random port in [51820, 51830].
	host, portStr, err := net.SplitHostPort(tun.Endpoint)
	if err != nil || host != "203.0.113.7" {
		t.Errorf("endpoint = %q, want host 203.0.113.7", tun.Endpoint)
	}
	if port, _ := strconv.Atoi(portStr); port < 51820 || port > 51830 {
		t.Errorf("endpoint port %s not in [51820, 51830]", portStr)
	}
	if tun.Address != "10.86.0.5" {
		t.Errorf("address = %q, want 10.86.0.5 (CIDR stripped)", tun.Address)
	}
	if tun.Obfuscation.Jc != 5 || tun.Obfuscation.H4 != 13 {
		t.Errorf("obfuscation not carried: %+v", tun.Obfuscation)
	}
	if len(tun.AllowedIPs) != 2 {
		t.Errorf("allowed-ips = %v", tun.AllowedIPs)
	}
	if tun.ServerPublicKey == "" || tun.PrivateKey == "" {
		t.Error("keys not carried into tunnel")
	}
}

// TestRandomEntryPool checks the client spreads across every IP in a node's
// endpoint pool (the random entry-point feature, decision 17) and stays within
// each entry's port range.
func TestRandomEntryPool(t *testing.T) {
	a := &AmneziaWG{
		Endpoints: []EndpointPool{
			{IP: "1.1.1.1", PortMin: 2000, PortMax: 3000},
			{IP: "2.2.2.2", PortMin: 2000, PortMax: 3000},
			{IP: "3.3.3.3", PortMin: 2000, PortMax: 3000},
		},
	}
	seen := map[string]bool{}
	for i := 0; i < 300; i++ {
		ep, err := a.dialEndpoint(nil)
		if err != nil {
			t.Fatalf("dialEndpoint: %v", err)
		}
		host, portStr, err := net.SplitHostPort(ep)
		if err != nil {
			t.Fatalf("bad endpoint %q: %v", ep, err)
		}
		if port, _ := strconv.Atoi(portStr); port < 2000 || port > 3000 {
			t.Fatalf("port %s out of [2000,3000]", portStr)
		}
		seen[host] = true
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if !seen[ip] {
			t.Errorf("entry IP %s never selected over 300 connects — not random", ip)
		}
	}
}

func TestParsePlaintext(t *testing.T) {
	p, err := Parse(writePlain(t, sampleProfile(t)), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.FleetID != "fleet-demo" || p.Revision != 7 || len(p.Profiles) != 1 || len(p.Profiles[0].Nodes) != 1 {
		t.Fatalf("profile fields wrong: %+v", p)
	}
	if p.Profiles[0].Name != "Amsterdam Direct" || p.Profiles[0].Protocol != "amneziawg" {
		t.Fatalf("client profile metadata wrong: %+v", p.Profiles[0])
	}
	assertResolvesToTunnel(t, p)
}

func TestParsePassword(t *testing.T) {
	data := writePassword(t, sampleProfile(t), "correct horse")
	p, err := Parse(data, Options{Password: "correct horse"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertResolvesToTunnel(t, p)

	// Wrong password is rejected (AEAD auth fails).
	if _, err := Parse(data, Options{Password: "nope"}); !errors.Is(err, crypto.ErrWrongPassword) {
		t.Errorf("wrong password: got %v, want ErrWrongPassword", err)
	}
	// No password at all → a clear "need a password" error.
	if _, err := Parse(data, Options{}); !errors.Is(err, ErrPasswordNeeded) {
		t.Errorf("missing password: got %v, want ErrPasswordNeeded", err)
	}
}

func TestParseAccount(t *testing.T) {
	recipientPriv := randBytes(t, 32)
	recipientPub, _ := curve25519.X25519(recipientPriv, curve25519.Basepoint)
	signerPub, signerPriv, _ := ed25519.GenerateKey(rand.Reader)

	data := writeAccount(t, sampleProfile(t), recipientPub, signerPriv)
	p, err := Parse(data, Options{DeviceKey: recipientPriv, SignerPublic: signerPub})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertResolvesToTunnel(t, p)

	// Missing keys → a clear error, not a crash.
	if _, err := Parse(data, Options{}); !errors.Is(err, ErrAccountKeyNeeded) {
		t.Errorf("missing keys: got %v, want ErrAccountKeyNeeded", err)
	}
	// A different signer key fails verification.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Parse(data, Options{DeviceKey: recipientPriv, SignerPublic: otherPub}); !errors.Is(err, crypto.ErrBadSignature) {
		t.Errorf("bad signer: got %v, want ErrBadSignature", err)
	}
}

func TestParseRejectsNonPharos(t *testing.T) {
	if _, err := Parse([]byte(`{"hello":"world"}`), Options{}); !errors.Is(err, ErrNotPharos) {
		t.Errorf("non-pharos json: got %v, want ErrNotPharos", err)
	}
	if _, err := Parse([]byte("not json"), Options{}); !errors.Is(err, ErrNotPharos) {
		t.Errorf("garbage: got %v, want ErrNotPharos", err)
	}
}

// TestXRayTunnelResolves checks that a node carrying both protocols resolves its
// XRay/REALITY entry into a dialable XRayTunnel (the controller emits this shape):
// the VLESS identity, the REALITY public key + camouflage, a TCP endpoint from
// the pool, and the CIDR-stripped utun address.
// TestClientProfileMTU checks the per-profile `mtu` the controller emits on a
// cascade profile round-trips through the bundle parse, that Select carries it,
// and that a direct profile (no mtu) reads 0 — the read path Prepare relies on
// to honour the hop-aware MTU and otherwise keep the 1420 default.
func TestClientProfileMTU(t *testing.T) {
	// A cascade profile carries the controller's reduced, hop-aware MTU.
	bundle := `{"fleet_id":"f","user":"u","profiles":[` +
		`{"id":"p_cascade","name":"EU Cascade","protocol":"amneziawg","mtu":1340,` +
		`"path":{"name":"c","hops":[{"id":"a","role":"entry"},{"id":"b","role":"exit"}]},"nodes":[]},` +
		`{"id":"p_direct","name":"Direct","protocol":"amneziawg","nodes":[]}]}`
	var p Profile
	if err := json.Unmarshal([]byte(bundle), &p); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	cascade, err := p.Select("p_cascade")
	if err != nil {
		t.Fatalf("select cascade: %v", err)
	}
	if cascade.MTU != 1340 {
		t.Fatalf("cascade MTU = %d, want 1340 (hop-aware)", cascade.MTU)
	}
	direct, err := p.Select("p_direct")
	if err != nil {
		t.Fatalf("select direct: %v", err)
	}
	if direct.MTU != 0 {
		t.Fatalf("direct MTU = %d, want 0 (client defaults to 1420)", direct.MTU)
	}
}

func TestXRayTunnelResolves(t *testing.T) {
	awg, _ := json.Marshal(AmneziaWG{
		PrivateKey: "cHJpdg==", Address: "10.86.0.9/32", PublicKey: "cHVi",
		Endpoints: []EndpointPool{{IP: "203.0.113.7", PortMin: 443, PortMax: 443}},
	})
	xray, _ := json.Marshal(XRayReality{
		UUID:        "11111111-1111-1111-1111-111111111111",
		Flow:        "xtls-rprx-vision",
		Address:     "10.86.0.9/32",
		PublicKey:   "reality-pub-key",
		ServerName:  "www.microsoft.com",
		ShortID:     "",
		Fingerprint: "chrome",
		Endpoints:   []EndpointPool{{IP: "203.0.113.7", PortMin: 443, PortMax: 443}},
		AllowedIPs:  []string{"0.0.0.0/0", "::/0"},
	})
	node := &Node{
		ID: "nod_x", Name: "ams", Region: "eu", Endpoints: []string{"203.0.113.7"},
		Protocols: []Protocol{
			{Type: "amneziawg", V: 2, Params: awg},
			{Type: "xray-reality", V: 1, Params: xray},
		},
	}

	if !node.HasXRayReality() {
		t.Fatal("HasXRayReality = false, want true")
	}

	tun, err := node.XRayTunnel()
	if err != nil {
		t.Fatalf("XRayTunnel: %v", err)
	}
	if tun.UUID != "11111111-1111-1111-1111-111111111111" || tun.Flow != "xtls-rprx-vision" {
		t.Errorf("vless identity not carried: %+v", tun)
	}
	if tun.PublicKey != "reality-pub-key" || tun.ServerName != "www.microsoft.com" || tun.Fingerprint != "chrome" {
		t.Errorf("reality camouflage not carried: %+v", tun)
	}
	if host, port, _ := net.SplitHostPort(tun.Endpoint); host != "203.0.113.7" || port != "443" {
		t.Errorf("endpoint = %q, want 203.0.113.7:443 (TCP)", tun.Endpoint)
	}
	if tun.Address != "10.86.0.9" {
		t.Errorf("address = %q, want 10.86.0.9 (CIDR stripped)", tun.Address)
	}
	if len(tun.AllowedIPs) != 2 {
		t.Errorf("allowed-ips = %v", tun.AllowedIPs)
	}

	// A node with only AmneziaWG has no XRay entry.
	awgOnly := &Node{Protocols: []Protocol{{Type: "amneziawg", V: 2, Params: awg}}}
	if awgOnly.HasXRayReality() {
		t.Error("HasXRayReality = true for an AmneziaWG-only node")
	}
	if _, err := awgOnly.XRayTunnel(); !errors.Is(err, ErrNoXRayReality) {
		t.Errorf("XRayTunnel on awg-only node: got %v, want ErrNoXRayReality", err)
	}
}
