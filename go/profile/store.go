// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrProfileNotFound is returned when a named profile is not in the store.
var ErrProfileNotFound = errors.New("profile: not found in store")

// Store is the on-device profile store. It keeps the raw `.pharos` files (still
// encrypted for password/account modes) under a directory — secrets are only
// decrypted in memory at connect time, never persisted in the clear. A flat
// directory of `<name>.pharos` is enough for the desktop client; mobile uses
// the platform keystore for the device key, not this store.
type Store struct {
	dir string
}

// NewStore opens or creates the profile store rooted at dir.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("profile: store dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("profile: create store dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// path returns the on-disk path for a profile name (sanitized to a basename).
func (s *Store) path(name string) string {
	name = strings.TrimSuffix(filepath.Base(name), Extension)
	return filepath.Join(s.dir, name+Extension)
}

// Import validates that data is a `.pharos` file (by header) and stores it under
// name, returning the stored path. It does not decrypt — secrets stay out of the
// store; the header sniff just rejects non-profiles early.
func (s *Store) Import(name string, data []byte) (string, error) {
	if _, err := header(data); err != nil {
		return "", err
	}
	p := s.path(name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", fmt.Errorf("profile: write %s: %w", p, err)
	}
	return p, nil
}

// Raw returns the stored raw `.pharos` bytes for name (still encrypted). The
// caller decrypts with Parse + the appropriate Options.
func (s *Store) Raw(name string) ([]byte, error) {
	data, err := os.ReadFile(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("profile: read %s: %w", name, err)
	}
	return data, nil
}

// Remove deletes a stored profile. Removing a missing profile is not an error.
func (s *Store) Remove(name string) error {
	err := os.Remove(s.path(name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("profile: remove %s: %w", name, err)
	}
	return nil
}

// Entry is a stored profile's summary for listing.
type Entry struct {
	Name string // store name (filename without extension)
	Enc  string // none | password | account (from the readable header)
}

// List returns the stored profiles, sorted by name, each with its encryption
// mode read from the always-readable header.
func (s *Store) List() ([]Entry, error) {
	matches, err := filepath.Glob(filepath.Join(s.dir, "*"+Extension))
	if err != nil {
		return nil, fmt.Errorf("profile: list store: %w", err)
	}
	out := make([]Entry, 0, len(matches))
	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), Extension)
		enc := "?"
		if data, err := os.ReadFile(m); err == nil {
			if h, err := header(data); err == nil {
				enc = h.Enc
			}
		}
		out = append(out, Entry{Name: name, Enc: enc})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// WrapPlaintext wraps a decrypted profile JSON in an `enc:none` `.pharos`
// envelope, so a profile fetched by account sync can be stored in the form the
// connect path already reads. The controller only ever held the sealed bundle;
// the decryption happened on this device.
func WrapPlaintext(profileJSON json.RawMessage) ([]byte, error) {
	return json.Marshal(envelope{
		Fmt:     formatTag,
		V:       formatVersion,
		Enc:     EncNone,
		Payload: profileJSON,
	})
}

// header parses just the always-readable envelope header, validating it is a
// pharos-profile file.
func header(data []byte) (envelope, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil || env.Fmt != formatTag {
		return envelope{}, ErrNotPharos
	}
	return env, nil
}
