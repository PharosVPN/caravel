// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package crypto is caravel's device-side reimplementation of PharosVPN's
// end-to-end profile crypto (DESIGN §8/§9) — the executable mirror of the
// controller's internal/e2e + internal/pharos. The controller only ever seals;
// the client opens. These primitives must match the controller byte-for-byte:
//   - password mode: Argon2id(t=1, m=64MiB, p=4) + XChaCha20-Poly1305, header AAD
//   - account mode:  X25519 key agreement + HKDF-SHA256 keywrap + XChaCha20-
//     Poly1305 payload, the whole bundle Ed25519-signed by the controller
//   - the per-user X25519 private key reaches a device as a passphrase-wrapped
//     blob (Argon2id + XChaCha20-Poly1305).
package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters — identical to the controller (internal/e2e, internal/
// pharos). Password mode also carries these in the file's kdf header.
const (
	ArgonTime    = 1
	ArgonMemory  = 64 * 1024 // KiB
	ArgonThreads = 4
	KeySize      = 32
	// wrapInfo domain-separates the account-mode key-wrap KDF (e2e.wrapInfo).
	wrapInfo = "pharosvpn/profile/keywrap/v1"
)

// Errors.
var (
	ErrWrongPassword   = errors.New("crypto: wrong password or corrupt file")
	ErrBadSignature    = errors.New("crypto: profile signature invalid")
	ErrDecrypt         = errors.New("crypto: profile could not be decrypted")
	ErrWrongPassphrase = errors.New("crypto: wrong passphrase or corrupt key blob")
)

// DeriveKEK derives a 32-byte key from a passphrase + salt (Argon2id), matching
// the controller's password mode and key-wrap KDF.
func DeriveKEK(passphrase string, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey([]byte(passphrase), salt, time, memory, threads, KeySize)
}

// OpenXChaCha opens an XChaCha20-Poly1305 ciphertext (24-byte nonce) with the
// given additional authenticated data (nil if none). A failure means a wrong
// key/password or a tampered file.
func OpenXChaCha(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return pt, nil
}

// SealedBundle is a profile sealed to one user (account mode) — the exact shape
// of the controller's e2e.SealedBundle, so JSON round-trips and the signature
// covers identical bytes.
type SealedBundle struct {
	V          int    `json:"v"`
	EphPublic  []byte `json:"epk"`
	WrapNonce  []byte `json:"wn"`
	WrappedKey []byte `json:"wk"`
	Nonce      []byte `json:"n"`
	Ciphertext []byte `json:"ct"`
	Signature  []byte `json:"sig"`
}

// signingBytes is the deterministic byte string the signature covers — the
// bundle as compact JSON with the signature field cleared (e2e.signingBytes).
func (b SealedBundle) signingBytes() ([]byte, error) {
	unsigned := b
	unsigned.Signature = nil
	return json.Marshal(unsigned)
}

// OpenSealed verifies a bundle's signature against signerPublic and decrypts it
// with the recipient's X25519 private key — the device-side mirror of e2e.Open.
func OpenSealed(b SealedBundle, recipientPrivate []byte, signerPublic ed25519.PublicKey) ([]byte, error) {
	signed, err := b.signingBytes()
	if err != nil {
		return nil, err
	}
	if len(signerPublic) != ed25519.PublicKeySize || !ed25519.Verify(signerPublic, signed, b.Signature) {
		return nil, ErrBadSignature
	}
	shared, err := curve25519.X25519(recipientPrivate, b.EphPublic)
	if err != nil {
		return nil, ErrDecrypt
	}
	dataKey, err := openX(deriveWrapKey(shared), b.WrapNonce, b.WrappedKey)
	if err != nil {
		return nil, ErrDecrypt
	}
	plaintext, err := openX(dataKey, b.Nonce, b.Ciphertext)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// wrappedKey is the on-disk form of a passphrase-sealed X25519 private key
// (e2e.wrappedKey) — how a per-user private key reaches a new device.
type wrappedKey struct {
	V     int    `json:"v"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"n"`
	CT    []byte `json:"ct"`
}

// UnwrapPrivateKey recovers a user's X25519 private key from a passphrase-wrapped
// blob (e2e.UnwrapPrivateKey). Needed to open account-mode profiles.
func UnwrapPrivateKey(passphrase string, blob []byte) ([]byte, error) {
	var wk wrappedKey
	if err := json.Unmarshal(blob, &wk); err != nil {
		return nil, ErrWrongPassphrase
	}
	private, err := openX(DeriveKEK(passphrase, wk.Salt, ArgonTime, ArgonMemory, ArgonThreads), wk.Nonce, wk.CT)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return private, nil
}

// VerifyProfileSignature reports whether sig is signerPublic's Ed25519 signature
// over signed.
func VerifyProfileSignature(signed, sig []byte, signerPublic ed25519.PublicKey) bool {
	return len(signerPublic) == ed25519.PublicKeySize && ed25519.Verify(signerPublic, signed, sig)
}

// openX opens an XChaCha20-Poly1305 ciphertext with no AAD, mapping failure to
// a decrypt error.
func openX(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// deriveWrapKey turns an X25519 shared secret into the 32-byte data-key wrap key
// (e2e.deriveWrapKey: HKDF-SHA256 with the keywrap info string).
func deriveWrapKey(shared []byte) []byte {
	r := hkdf.New(sha256.New, shared, nil, []byte(wrapInfo))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		panic("crypto: hkdf failed: " + err.Error())
	}
	return key
}
