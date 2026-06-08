// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package sync

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"

	"github.com/PharosVPN/caravel/core/crypto"
	"github.com/PharosVPN/caravel/core/deviceid"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// wrapInfo mirrors the controller's e2e key-wrap domain separator (must match
// crypto.deriveWrapKey / e2e.deriveWrapKey).
const wrapInfo = "pharosvpn/profile/keywrap/v1"

// sealForTest mirrors the controller's e2e.Seal byte-for-byte: it encrypts
// plaintext to recipientPublic (X25519) and signs the bundle with signer
// (Ed25519). caravel's crypto.OpenSealed must open exactly this.
func sealForTest(t *testing.T, plaintext, recipientPublic []byte, signer ed25519.PrivateKey) []byte {
	t.Helper()
	dataKey := randBytes(t, 32)
	payload, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := randBytes(t, payload.NonceSize())
	ct := payload.Seal(nil, nonce, plaintext, nil)

	ephPriv := randBytes(t, 32)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(ephPriv, recipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := chacha20poly1305.NewX(deriveWrapKeyTest(shared))
	if err != nil {
		t.Fatal(err)
	}
	wrapNonce := randBytes(t, wrap.NonceSize())

	b := crypto.SealedBundle{
		V:          1,
		EphPublic:  ephPub,
		WrapNonce:  wrapNonce,
		WrappedKey: wrap.Seal(nil, wrapNonce, dataKey, nil),
		Nonce:      nonce,
		Ciphertext: ct,
	}
	unsigned := b
	unsigned.Signature = nil
	signed, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = ed25519.Sign(signer, signed)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func deriveWrapKeyTest(shared []byte) []byte {
	r := hkdf.New(sha256.New, shared, nil, []byte(wrapInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(err)
	}
	return key
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPerDeviceDecrypt is the headline case: a profile sealed to the DEVICE's own
// X25519 key opens with that key drawn from the bundle (no account passphrase) —
// the join-link path, where coxswain returns an EMPTY wrapped_private_key.
func TestPerDeviceDecrypt(t *testing.T) {
	device, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"fleet_id":"f","user":"u"}`)
	sealed := sealForTest(t, plaintext, device.Public, signPriv)

	// Build a join-link bundle carrying the device's own X25519 private key.
	encPEM, err := deviceid.EncodeEncryptionKey(device.Private)
	if err != nil {
		t.Fatal(err)
	}
	bundle := deviceid.Bundle{EncryptionKeyPEM: encPEM}
	devicePriv, err := bundle.EncryptionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	rp := &RemoteProfile{
		Ciphertext:        sealed,
		SigningPublicKey:  signPub,
		WrappedPrivateKey: nil, // EMPTY for a per-device device
	}
	key, err := decryptionKey(devicePriv, "", rp.WrappedPrivateKey)
	if err != nil {
		t.Fatalf("decryptionKey (per-device): %v", err)
	}
	got, err := openProfile(rp, key)
	if err != nil {
		t.Fatalf("openProfile (per-device): %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("per-device decrypt mismatch: got %q", got)
	}

	// A foreign device key must NOT open it (the seal is to this device).
	other, _ := crypto.GenerateKeyPair()
	if _, err := openProfile(rp, other.Private); err == nil {
		t.Error("a foreign device key opened the per-device bundle")
	}
}

// TestLegacyPassphraseDecrypt guards back-compat: a bundle with NO device key
// (the account-sync shape) still opens via the passphrase-wrapped account key.
func TestLegacyPassphraseDecrypt(t *testing.T) {
	const passphrase = "correct horse battery staple"
	account, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.WrapPrivateKey(passphrase, account.Private)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"fleet_id":"legacy","user":"u2"}`)
	sealed := sealForTest(t, plaintext, account.Public, signPriv)

	// Legacy bundle: no device key (EncryptionPrivateKey returns nil).
	bundle := deviceid.Bundle{}
	devicePriv, err := bundle.EncryptionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if devicePriv != nil {
		t.Fatal("legacy bundle should carry no device key")
	}

	rp := &RemoteProfile{
		Ciphertext:        sealed,
		SigningPublicKey:  signPub,
		WrappedPrivateKey: wrapped, // coxswain returns the wrapped account key
	}
	key, err := decryptionKey(devicePriv, passphrase, rp.WrappedPrivateKey)
	if err != nil {
		t.Fatalf("decryptionKey (legacy): %v", err)
	}
	got, err := openProfile(rp, key)
	if err != nil {
		t.Fatalf("openProfile (legacy): %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("legacy decrypt mismatch: got %q", got)
	}

	// A wrong passphrase fails to unwrap.
	if _, err := decryptionKey(devicePriv, "wrong", rp.WrappedPrivateKey); err == nil {
		t.Error("a wrong passphrase unwrapped the account key")
	}
}
