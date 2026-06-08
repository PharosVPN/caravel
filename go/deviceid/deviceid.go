// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package deviceid parses the caravel device-identity bundle (`.pharosid`) — the
// device-side mirror of the controller's internal/deviceid. The bundle holds the
// mTLS client leaf a device presents to a relay to reach AccountSync, plus how to
// find and verify that relay. `cox devices issue` writes one; the operator copies
// it to the device; caravel imports it. The account passphrase is NOT in the
// bundle — it authenticates separately at AccountSync.Authenticate.
//
// A join-link-enrolled device additionally carries EncryptionKeyPEM — the
// device's OWN X25519 private key. coxswain seals that device's profile bundle to
// the matching public key, so the device opens its bundle with this key and NO
// account passphrase (the passphrase-less enrollment flow). A legacy
// account-sync `.pharosid` (issued by `cox devices issue`) omits it.
package deviceid

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// EncryptionKeyPEMType is the PEM block type for the device's X25519 private key
// (a raw 32-byte scalar wrapped in PEM so it sits alongside the other PEM fields).
const EncryptionKeyPEMType = "X25519 PRIVATE KEY"

// Format constants — must match the controller (internal/deviceid).
const (
	FormatTag     = "pharos-device"
	FormatVersion = 1
	Extension     = ".pharosid"
)

// Bundle is a device's relayed-sync identity. The device dials RelayAddr with its
// DeviceCert leaf (RootCAs = FleetCA, ServerName = RelayServerName), then speaks
// AccountSync over that mTLS channel.
type Bundle struct {
	Fmt             string `json:"fmt"`
	V               int    `json:"v"`
	User            string `json:"user,omitempty"`
	Alias           string `json:"alias,omitempty"`
	RelayAddr       string `json:"relay_addr"`
	RelayServerName string `json:"relay_server_name"`
	CAFingerprint   string `json:"ca_fingerprint,omitempty"`
	FleetCAPEM      string `json:"fleet_ca"`
	DeviceCertPEM   string `json:"device_cert"`
	DeviceKeyPEM    string `json:"device_key"`
	// SigningPublicKey is coxswain's Ed25519 profile-signing public key, carried so
	// a join-link device can verify sealed bundles it later fetches with GetProfile
	// without first re-learning it. Optional; GetProfile also returns it.
	SigningPublicKey []byte `json:"signing_public_key,omitempty"`
	// EncryptionKeyPEM is the device's OWN X25519 PRIVATE key (PEM, type
	// "X25519 PRIVATE KEY"), present only on a join-link-enrolled device. It opens
	// the per-device-sealed profile bundle — no account passphrase. Empty for a
	// legacy account-sync bundle, which decrypts via the passphrase-wrapped key.
	EncryptionKeyPEM string `json:"encryption_key,omitempty"`
}

// EncryptionPrivateKey decodes the device's X25519 private key from
// EncryptionKeyPEM, or returns (nil, nil) when the bundle carries none (a legacy
// account-sync bundle). A present-but-malformed key is an error.
func (b Bundle) EncryptionPrivateKey() ([]byte, error) {
	if b.EncryptionKeyPEM == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(b.EncryptionKeyPEM))
	if block == nil || block.Type != EncryptionKeyPEMType {
		return nil, errors.New("deviceid: malformed encryption key PEM")
	}
	if len(block.Bytes) != 32 {
		return nil, fmt.Errorf("deviceid: encryption key must be 32 bytes, got %d", len(block.Bytes))
	}
	return block.Bytes, nil
}

// EncodeEncryptionKey wraps a raw 32-byte X25519 private key as the PEM string
// stored in EncryptionKeyPEM.
func EncodeEncryptionKey(priv []byte) (string, error) {
	if len(priv) != 32 {
		return "", fmt.Errorf("deviceid: encryption key must be 32 bytes, got %d", len(priv))
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: EncryptionKeyPEMType, Bytes: priv})), nil
}

// Marshal encodes the bundle as the on-disk `.pharosid` JSON.
func (b Bundle) Marshal() ([]byte, error) {
	if b.Fmt == "" {
		b.Fmt = FormatTag
	}
	if b.V == 0 {
		b.V = FormatVersion
	}
	return json.Marshal(b)
}

// Parse decodes and validates a `.pharosid` file.
func Parse(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("deviceid: %w", err)
	}
	if b.Fmt != FormatTag {
		return Bundle{}, errors.New("deviceid: not a pharos-device bundle")
	}
	if b.V != FormatVersion {
		return Bundle{}, fmt.Errorf("deviceid: unsupported version %d", b.V)
	}
	if err := b.validate(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

func (b Bundle) validate() error {
	switch {
	case b.RelayAddr == "":
		return errors.New("deviceid: missing relay_addr")
	case b.FleetCAPEM == "":
		return errors.New("deviceid: missing fleet_ca")
	case b.DeviceCertPEM == "":
		return errors.New("deviceid: missing device_cert")
	case b.DeviceKeyPEM == "":
		return errors.New("deviceid: missing device_key")
	}
	return nil
}
