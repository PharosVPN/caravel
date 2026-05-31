// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package crypto handles E2E key management and profile decryption.
package crypto

import (
	"crypto/ed25519"
)

// DeviceKey is the per-device Ed25519 keypair (stored in platform keystore).
type DeviceKey struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// UnwrapProfileKey decrypts a profile's private key with a passphrase.
// Uses Argon2id (DESIGN §9, decision 9).
func UnwrapProfileKey(passphraseWrappedBlob []byte, passphrase string) (ed25519.PrivateKey, error) {
	// TODO: Argon2id(passphrase) → key
	// TODO: XChaCha20-Poly1305 decrypt wrapped blob
	return nil, nil
}

// VerifyProfileSignature checks the profile's signing key against coxswain's public key.
func VerifyProfileSignature(profileData []byte, signature []byte, coxswainSigningKey ed25519.PublicKey) bool {
	// TODO: ed25519.Verify
	return false
}
