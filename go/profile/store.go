// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package profile manages the local profile store and .pharos format.
package profile

// Profile is a parsed .pharos file (plaintext or decrypted).
type Profile struct {
	// Device (tunnel endpoint info)
	EntryEndpoint string // e.g., "vpn.example.com:443"
	EntryKey      string // server public key
	
	// Protocol set (may include AmneziaWG, XRay, etc.)
	Protocols []string
	
	// Obfuscation (per-node parameters for AmneziaWG)
	Obfuscation map[string]string
}

// ImportProfile parses a .pharos file and applies it to the local store.
// enc: "none" (plaintext), "password" (Argon2id), "account" (device key)
func ImportProfile(profileData []byte, enc string, passphrase string) (*Profile, error) {
	// TODO: parse .pharos header, dispatch to decoder based on enc
	// - none: unmarshal directly
	// - password: Argon2id(passphrase) → key, decrypt with XChaCha20-Poly1305
	// - account: decrypt with stored device key
	return &Profile{}, nil
}

// Store is the local profile store (SQLite on-device).
type Store struct {
	// path to SQLite DB
}

// NewStore opens or creates the profile store.
func NewStore(dbPath string) (*Store, error) {
	// TODO: open SQLite, create schema if needed
	return &Store{}, nil
}

// Save persists a profile to the store.
func (s *Store) Save(name string, p *Profile) error {
	// TODO: insert/update in profiles table
	return nil
}

// Load retrieves a profile by name.
func (s *Store) Load(name string) (*Profile, error) {
	// TODO: query profiles table, unmarshal
	return &Profile{}, nil
}

// List returns all stored profiles.
func (s *Store) List() ([]*Profile, error) {
	// TODO: query all profiles
	return []*Profile{}, nil
}
