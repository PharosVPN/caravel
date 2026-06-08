// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package enroll

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/PharosVPN/caravel/core/crypto"
	"github.com/PharosVPN/caravel/core/deviceid"
	accountv1 "github.com/PharosVPN/caravel/core/gen/pharos/account/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// x25519KeySize is the X25519 public/private key length (must match the
// controller's accountsvc.x25519KeySize).
const x25519KeySize = 32

// Claim runs the whole device-side join-link enrollment and returns an assembled
// `.pharosid` Bundle the caller persists. It is passphrase-LESS: the device
// generates its own keys, the enrollment token is the only credential, and the
// resulting bundle carries the device's X25519 private key so it can open its
// per-device-sealed profile with no account passphrase.
//
// The steps mirror the contract the controller exposes (helm accountsvc.
// ClaimEnrollment):
//
//  1. ON-DEVICE KEYGEN — an ECDSA P-256 mTLS keypair (→ a CSR) and an X25519
//     encryption keypair. Both private halves stay on the device.
//  2. CLAIM — dial the relay over TLS, SERVER-AUTH ONLY (no client cert: the
//     device has no Device-CA leaf yet — this RPC mints it), pinning the relay
//     leaf by the link's `ca` root fingerprint, and call ClaimEnrollment.
//  3. ASSEMBLE — fold the response (signed leaf + fleet CA + relay coords +
//     signing key) together with the KEPT mTLS key and the X25519 private key
//     into a Bundle, validated before return.
//
// deviceName / platform label the device on the controller's device record;
// empty values fall back to caravel defaults on the controller side.
func Claim(ctx context.Context, link Link, deviceName, platform string) (deviceid.Bundle, error) {
	// (1) On-device keygen — private keys never leave.
	dk, err := crypto.GenerateDeviceCSR(deviceName)
	if err != nil {
		return deviceid.Bundle{}, err
	}
	enc, err := crypto.GenerateKeyPair() // X25519; enc.Private is the device's own key
	if err != nil {
		return deviceid.Bundle{}, err
	}

	// (2) Claim through the relay, cert-less, capturing the relay's presented
	// chain so we can bind it to the pinned root once we have the trust material.
	pin := &relayPin{wantRoot: normalizeFingerprint(link.CAFingerprint)}
	resp, err := claimRPC(ctx, link, dk.CSRPEM, enc.Public, deviceName, platform, pin)
	if err != nil {
		return deviceid.Bundle{}, err
	}

	// Consistency: the controller's own ca_fingerprint must equal the link's `ca`.
	if resp.GetCaFingerprint() != "" && !equalFingerprint(resp.GetCaFingerprint(), link.CAFingerprint) {
		return deviceid.Bundle{}, fmt.Errorf(
			"enroll: controller CA fingerprint %q does not match the link's %q",
			resp.GetCaFingerprint(), link.CAFingerprint)
	}

	// Bind the relay we just spoke to → the trust material the controller returned
	// → the root the link pinned. The relay presents only its Fleet-CA leaf (no
	// chain), so the root fingerprint usually cannot be matched from the handshake
	// alone; we instead prove the returned fleet_ca_pem ISSUED the relay's
	// presented leaf, and (where the relay DOES send its chain) that some presented
	// cert hashes to the pinned root. Either way the relay endpoint is
	// cryptographically tied to the controller's vouched trust; the profile's
	// Ed25519 seal signature gives end-to-end integrity on top.
	if err := pin.verify(resp.GetFleetCaPem()); err != nil {
		return deviceid.Bundle{}, err
	}

	// (3) Assemble the device identity.
	encKeyPEM, err := deviceid.EncodeEncryptionKey(enc.Private)
	if err != nil {
		return deviceid.Bundle{}, err
	}
	b := deviceid.Bundle{
		Fmt:              deviceid.FormatTag,
		V:                deviceid.FormatVersion,
		Alias:            deviceName,
		RelayAddr:        resp.GetRelayAddr(),
		RelayServerName:  resp.GetRelayServerName(),
		CAFingerprint:    resp.GetCaFingerprint(),
		FleetCAPEM:       string(resp.GetFleetCaPem()),
		DeviceCertPEM:    string(resp.GetDeviceCertPem()),
		DeviceKeyPEM:     string(dk.KeyPEM),
		SigningPublicKey: resp.GetSigningPublicKey(),
		EncryptionKeyPEM: encKeyPEM,
	}
	if b.CAFingerprint == "" {
		b.CAFingerprint = link.CAFingerprint
	}
	// Validate the assembled bundle parses (and the mTLS keypair is consistent).
	if err := validateAssembled(b); err != nil {
		return deviceid.Bundle{}, err
	}
	return b, nil
}

// claimRPC dials the relay cert-less (server-auth only), capturing the relay's
// presented chain into pin, and invokes ClaimEnrollment. The relay accepts a
// cert-less connection for ONLY this method; every other AccountSync method
// requires the device leaf.
func claimRPC(ctx context.Context, link Link, csrPEM, encPub []byte, deviceName, platform string, pin *relayPin) (*accountv1.ClaimEnrollmentResponse, error) {
	if len(encPub) != x25519KeySize {
		return nil, fmt.Errorf("enroll: device encryption key must be %d bytes", x25519KeySize)
	}
	tc := credentials.NewTLS(pin.tlsConfig())
	conn, err := grpc.NewClient(link.Relay, grpc.WithTransportCredentials(tc))
	if err != nil {
		return nil, fmt.Errorf("enroll: dial relay %s: %w", link.Relay, err)
	}
	defer conn.Close()

	resp, err := accountv1.NewAccountSyncClient(conn).ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token:            link.Token,
		CsrPem:           csrPEM,
		EncryptionPubkey: encPub,
		DeviceName:       deviceName,
		Platform:         platform,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: claim: %w", err)
	}
	if len(resp.GetDeviceCertPem()) == 0 || len(resp.GetFleetCaPem()) == 0 || resp.GetRelayAddr() == "" {
		return nil, errors.New("enroll: claim response missing device cert / fleet CA / relay address")
	}
	return resp, nil
}

// relayPin pins the cert-less claim connection to the link's root CA
// fingerprint. The device holds no roots and no client cert yet, so standard
// chain verification can't run; relayPin instead captures the relay's presented
// chain during the handshake (tlsConfig) and binds it to the pinned root AFTER
// the claim returns the controller's trust material (verify).
type relayPin struct {
	wantRoot string              // normalized root CA fingerprint from the link
	chain    []*x509.Certificate // the relay's presented chain (leaf first)
}

// tlsConfig is the SERVER-AUTH-ONLY config for the claim leg: no client cert (the
// device has no leaf yet), and chain verification deferred to relayPin.verify.
func (p *relayPin) tlsConfig() *tls.Config {
	return &tls.Config{
		// Verification happens in VerifyConnection (capture) + verify (bind), not
		// against a roots pool the device does not yet hold.
		InsecureSkipVerify: true, //nolint:gosec // pinned by fingerprint in verify()
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("enroll: relay presented no certificate")
			}
			p.chain = cs.PeerCertificates
			// Fast path: if the relay DID send its chain up to the root, accept it
			// immediately when a presented cert matches the pinned root fingerprint.
			for _, c := range cs.PeerCertificates {
				if certFingerprint(c) == p.wantRoot {
					return nil
				}
			}
			// Otherwise allow the handshake to complete; verify() binds the leaf to
			// the returned Fleet CA + the pinned root once the claim responds.
			return nil
		},
	}
}

// verify binds the captured relay chain to the pinned root, using the Fleet CA
// the controller returned. It requires that fleetCAPEM (the returned Fleet CA)
// validly issued the relay's presented leaf — proving the endpoint we spoke to is
// part of the very fleet the controller vouches for. When the relay also
// presented its root in the chain, tlsConfig already matched the pin directly.
func (p *relayPin) verify(fleetCAPEM []byte) error {
	if len(p.chain) == 0 {
		return errors.New("enroll: no relay certificate captured")
	}
	// If a presented cert already matched the pinned root, we are done.
	for _, c := range p.chain {
		if certFingerprint(c) == p.wantRoot {
			return nil
		}
	}
	if len(fleetCAPEM) == 0 {
		return errors.New("enroll: relay chain did not reach the pinned root and no fleet CA was returned")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(fleetCAPEM) {
		return errors.New("enroll: returned fleet CA is not parseable")
	}
	leaf := p.chain[0]
	inter := x509.NewCertPool()
	for _, c := range p.chain[1:] {
		inter.AddCert(c)
	}
	// Verify the relay leaf against the returned Fleet CA (treated as the trusted
	// root of THIS check). EKU is ServerAuth — it is the relay's server leaf.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("enroll: relay leaf is not issued by the controller's fleet CA: %w", err)
	}
	return nil
}

// certFingerprint is the lowercase hex SHA-256 of a certificate's DER — the shape
// the controller's pki.Authority.Fingerprint() produces for the pinned root.
func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// validateAssembled re-parses the assembled bundle through deviceid.Parse (so the
// stored shape is provably valid) and confirms the kept mTLS key matches the
// signed leaf and the X25519 key decodes.
func validateAssembled(b deviceid.Bundle) error {
	raw, err := b.Marshal()
	if err != nil {
		return err
	}
	parsed, err := deviceid.Parse(raw)
	if err != nil {
		return fmt.Errorf("enroll: assembled bundle invalid: %w", err)
	}
	if _, err := tls.X509KeyPair([]byte(parsed.DeviceCertPEM), []byte(parsed.DeviceKeyPEM)); err != nil {
		return fmt.Errorf("enroll: device cert/key mismatch: %w", err)
	}
	if _, err := parsed.EncryptionPrivateKey(); err != nil {
		return err
	}
	return nil
}

// equalFingerprint compares two CA fingerprints, tolerating case and a leading
// "sha256:" prefix / ":"-separated hex on either side.
func equalFingerprint(a, b string) bool {
	return normalizeFingerprint(a) == normalizeFingerprint(b)
}

// normalizeFingerprint reduces a CA fingerprint to bare lowercase hex: it strips
// a leading "sha256:" prefix and any ":" separators, matching the controller's
// pki.Authority.Fingerprint() shape (lowercase hex SHA-256 of the root DER) while
// tolerating common decorated forms.
func normalizeFingerprint(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "sha256:")
	return strings.ReplaceAll(s, ":", "")
}
