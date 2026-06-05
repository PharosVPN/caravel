// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package deviceid parses the caravel device-identity bundle (`.pharosid`) — the
// device-side mirror of the controller's internal/deviceid. The bundle holds the
// mTLS client leaf a device presents to a relay to reach AccountSync, plus how to
// find and verify that relay. `cox devices issue` writes one; the operator copies
// it to the device; caravel imports it. The account passphrase is NOT in the
// bundle — it authenticates separately at AccountSync.Authenticate.
package deviceid

import (
	"encoding/json"
	"errors"
	"fmt"
)

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
	RelayAddr       string `json:"relay_addr"`
	RelayServerName string `json:"relay_server_name"`
	CAFingerprint   string `json:"ca_fingerprint,omitempty"`
	FleetCAPEM      string `json:"fleet_ca"`
	DeviceCertPEM   string `json:"device_cert"`
	DeviceKeyPEM    string `json:"device_key"`
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
