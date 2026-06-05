// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package crypto

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// saltSize is the Argon2id salt length for passphrase wrapping (e2e.saltSize).
const saltSize = 16

// KeyPair is a user's X25519 encryption keypair (e2e.KeyPair). On first-device
// setup the device generates one, keeps Private locally, and sends the
// controller Public plus a passphrase-wrapped Private (it never sees Private).
type KeyPair struct {
	Public  []byte
	Private []byte
}

// GenerateKeyPair mints a fresh X25519 keypair (e2e.GenerateKeyPair) for first
// device enrollment.
func GenerateKeyPair() (KeyPair, error) {
	priv := randomBytes(KeySize)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("crypto: derive public key: %w", err)
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

// WrapPrivateKey seals private under a passphrase-derived key (e2e.WrapPrivateKey),
// producing the opaque blob the controller stores. The format round-trips with
// UnwrapPrivateKey byte-for-byte.
func WrapPrivateKey(passphrase string, private []byte) ([]byte, error) {
	salt := randomBytes(saltSize)
	aead, err := chacha20poly1305.NewX(DeriveKEK(passphrase, salt, ArgonTime, ArgonMemory, ArgonThreads))
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(aead.NonceSize())
	return json.Marshal(wrappedKey{
		V:     1,
		Salt:  salt,
		Nonce: nonce,
		CT:    aead.Seal(nil, nonce, private, nil),
	})
}

// randomBytes returns n cryptographically random bytes; a failing system random
// source is unrecoverable.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic("crypto: crypto/rand unavailable: " + err.Error())
	}
	return b
}
