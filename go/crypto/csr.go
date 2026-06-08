// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// DeviceKeypair is a freshly generated device mTLS keypair: a PKCS#10 CSR (the
// public half, for the controller to sign into the Device-CA leaf) and the
// PEM-encoded private key the device keeps. The private key NEVER leaves the
// device — only CSRPEM crosses the wire on a claim.
type DeviceKeypair struct {
	CSRPEM []byte // PEM CERTIFICATE REQUEST — sent to the controller
	KeyPEM []byte // PEM PRIVATE KEY (PKCS#8) — kept locally, becomes the bundle's device_key
}

// GenerateDeviceCSR mints an on-device ECDSA P-256 keypair and a PKCS#10 CSR for
// the mTLS device leaf — the executable mirror of the controller-side test
// helper (cli.deviceCSR / accountsvc deviceCSR). The controller's SignDeviceCSR
// verifies only the CSR self-signature and assigns the Subject/EKU itself, so the
// CommonName here is cosmetic; we set it to the device name for readability.
//
// The matching private key is returned PEM-encoded for the caller to persist in
// the device's `.pharosid`; it is never transmitted.
func GenerateDeviceCSR(commonName string) (DeviceKeypair, error) {
	if commonName == "" {
		commonName = "caravel-device"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return DeviceKeypair{}, fmt.Errorf("crypto: generate device key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(crand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return DeviceKeypair{}, fmt.Errorf("crypto: create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return DeviceKeypair{}, fmt.Errorf("crypto: marshal device key: %w", err)
	}
	return DeviceKeypair{
		CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}
