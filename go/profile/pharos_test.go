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
		Nodes: []Node{{
			ID:        "nod_ams1",
			Name:      "Amsterdam-1",
			Region:    "eu-nl",
			Endpoints: []string{"203.0.113.7"},
			Protocols: []Protocol{{Type: "amneziawg", V: 2, Params: raw}},
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
	node, err := p.Node("")
	if err != nil {
		t.Fatalf("Node: %v", err)
	}
	tun, err := node.Tunnel()
	if err != nil {
		t.Fatalf("Tunnel: %v", err)
	}
	if tun.Endpoint != "203.0.113.7:51820" {
		t.Errorf("endpoint = %q, want 203.0.113.7:51820", tun.Endpoint)
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

func TestParsePlaintext(t *testing.T) {
	p, err := Parse(writePlain(t, sampleProfile(t)), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.FleetID != "fleet-demo" || p.Revision != 7 || len(p.Nodes) != 1 {
		t.Fatalf("profile fields wrong: %+v", p)
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
