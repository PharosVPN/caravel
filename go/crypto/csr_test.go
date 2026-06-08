// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestGenerateDeviceCSR proves the on-device keygen yields a valid PKCS#10 CSR
// (ECDSA P-256, self-signature valid — what helm's SignDeviceCSR verifies) and a
// matching PKCS#8 private key the device keeps.
func TestGenerateDeviceCSR(t *testing.T) {
	dk, err := GenerateDeviceCSR("my-device")
	if err != nil {
		t.Fatalf("GenerateDeviceCSR: %v", err)
	}

	block, _ := pem.Decode(dk.CSRPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM block: %v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR self-signature invalid: %v", err)
	}
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("CSR public key is not ECDSA: %T", csr.PublicKey)
	}

	keyBlock, _ := pem.Decode(dk.KeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM block: %v", keyBlock)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is not ECDSA: %T", key)
	}

	// The CSR's public key must match the kept private key.
	if !ecKey.PublicKey.Equal(csr.PublicKey) {
		t.Error("CSR public key does not match the kept private key")
	}
}
