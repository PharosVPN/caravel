// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package enroll_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/PharosVPN/caravel/core/deviceid"
	"github.com/PharosVPN/caravel/core/enroll"
	accountv1 "github.com/PharosVPN/caravel/core/gen/pharos/account/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ── a minimal three-tier CA mirroring helm's pki (root → {fleet, device}) ──

type ca struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newRoot(t *testing.T) ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return ca{cert: cert, key: key, certPEM: pemCert(der)}
}

func newIntermediate(t *testing.T, parent ca, cn string) ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("intermediate %s: %v", cn, err)
	}
	cert, _ := x509.ParseCertificate(der)
	return ca{cert: cert, key: key, certPEM: pemCert(der)}
}

// issueLeaf signs a server leaf off ca for the given IP SAN (the relay's leaf).
func issueServerLeaf(t *testing.T, signer ca, ip net.IP) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
		DNSNames:     []string{"relay"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &key.PublicKey, signer.key)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der}, // single leaf — mirrors the relay (no chain bundled)
		PrivateKey:  key,
		Leaf:        mustParse(der),
	}
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustParse(der []byte) *x509.Certificate {
	c, _ := x509.ParseCertificate(der)
	return c
}

func rootFingerprint(root ca) string {
	sum := sha256.Sum256(root.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// claimServer is a stub AccountSync server that only implements ClaimEnrollment.
type claimServer struct {
	accountv1.UnimplementedAccountSyncServer
	deviceCA   ca
	fleetCAPEM []byte
	relayAddr  string
	relaySAN   string
	caFP       string
	signingPub []byte

	// captured request fields, for assertions.
	gotToken  string
	gotEncPub []byte
	gotName   string
	gotPlat   string
}

func (s *claimServer) ClaimEnrollment(_ context.Context, req *accountv1.ClaimEnrollmentRequest) (*accountv1.ClaimEnrollmentResponse, error) {
	s.gotToken = req.GetToken()
	s.gotEncPub = req.GetEncryptionPubkey()
	s.gotName = req.GetDeviceName()
	s.gotPlat = req.GetPlatform()
	leaf := signDeviceCSRPanic(s.deviceCA, req.GetCsrPem())
	return &accountv1.ClaimEnrollmentResponse{
		DeviceCertPem:    leaf,
		FleetCaPem:       s.fleetCAPEM,
		RelayAddr:        s.relayAddr,
		RelayServerName:  s.relaySAN,
		CaFingerprint:    s.caFP,
		SigningPublicKey: s.signingPub,
	}, nil
}

// signDeviceCSRPanic is the non-*testing.T variant used inside the gRPC handler.
func signDeviceCSRPanic(deviceCA ca, csrPEM []byte) []byte {
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		panic("bad CSR in handler")
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "caravel-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, deviceCA.cert, csr.PublicKey, deviceCA.key)
	if err != nil {
		panic(err)
	}
	return pemCert(der)
}

// startRelay brings up a TLS gRPC server presenting the relay leaf (server-auth
// only, no client cert required) on 127.0.0.1, returning its host:port and the
// captured-request server.
func startRelay(t *testing.T, srv *claimServer, relayLeaf tls.Certificate) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{relayLeaf},
		ClientAuth:   tls.VerifyClientCertIfGiven, // accept cert-less, like the relay
		MinVersion:   tls.VersionTLS12,
	})))
	accountv1.RegisterAccountSyncServer(gs, srv)
	go gs.Serve(lis) //nolint:errcheck
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

// buildFleet wires a root → {fleet, device} CA, a relay leaf issued off Fleet,
// and a running relay; it returns the started server stub and the join Link the
// device would scan.
func buildFleet(t *testing.T) (*claimServer, enroll.Link) {
	t.Helper()
	root := newRoot(t)
	fleet := newIntermediate(t, root, "Test Fleet CA")
	deviceCA := newIntermediate(t, root, "Test Device CA")
	relayLeaf := issueServerLeaf(t, fleet, net.IPv4(127, 0, 0, 1))

	srv := &claimServer{
		deviceCA:   deviceCA,
		fleetCAPEM: fleet.certPEM,
		relaySAN:   "relay",
		caFP:       rootFingerprint(root),
		signingPub: make([]byte, 32), // a placeholder Ed25519 pub (not exercised here)
	}
	addr := startRelay(t, srv, relayLeaf)
	srv.relayAddr = addr

	return srv, enroll.Link{
		Relay:         addr,
		Token:         "test-token",
		CAFingerprint: rootFingerprint(root),
	}
}

func TestClaimAssemblesBundle(t *testing.T) {
	srv, link := buildFleet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b, err := enroll.Claim(ctx, link, "my-laptop", "caravel")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// The assembled bundle parses + validates.
	raw, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := deviceid.Parse(raw)
	if err != nil {
		t.Fatalf("assembled bundle does not parse: %v", err)
	}

	// It carries the device's X25519 private key (32 bytes), the kept mTLS key,
	// the signed leaf, the fleet CA, and the relay coordinates.
	priv, err := parsed.EncryptionPrivateKey()
	if err != nil {
		t.Fatalf("EncryptionPrivateKey: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("device X25519 key: got %d bytes want 32", len(priv))
	}
	if _, err := tls.X509KeyPair([]byte(parsed.DeviceCertPEM), []byte(parsed.DeviceKeyPEM)); err != nil {
		t.Fatalf("device cert/key do not pair: %v", err)
	}
	if parsed.RelayAddr != srv.relayAddr || parsed.RelayServerName != "relay" {
		t.Errorf("relay coords: addr=%q name=%q", parsed.RelayAddr, parsed.RelayServerName)
	}
	if parsed.FleetCAPEM == "" {
		t.Error("bundle missing fleet CA")
	}

	// The device presented its 32-byte X25519 key and the labels to the relay.
	if len(srv.gotEncPub) != 32 {
		t.Errorf("controller saw enc pubkey of %d bytes", len(srv.gotEncPub))
	}
	if srv.gotToken != "test-token" {
		t.Errorf("controller saw token %q", srv.gotToken)
	}
	if srv.gotName != "my-laptop" || srv.gotPlat != "caravel" {
		t.Errorf("controller saw name=%q platform=%q", srv.gotName, srv.gotPlat)
	}
}

func TestClaimRejectsWrongCAFingerprint(t *testing.T) {
	_, link := buildFleet(t)
	link.CAFingerprint = "00" + link.CAFingerprint[2:] // flip the pin
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := enroll.Claim(ctx, link, "x", "caravel"); err == nil {
		t.Fatal("Claim accepted a relay whose root does not match the pinned fingerprint")
	}
}

// TestClaimRejectsImpostorRelay is the MITM case: an attacker stands up a relay
// with a leaf from a FOREIGN fleet CA and replays the legit controller's
// ca_fingerprint + an unrelated fleet_ca_pem. The consistency check passes (the
// fingerprint matches the link), so the bind step must catch it — the attacker's
// leaf is not issued by the fleet CA the controller returns.
func TestClaimRejectsImpostorRelay(t *testing.T) {
	// Legit fleet — the link pins this root, and the server returns this fleet CA.
	legitRoot := newRoot(t)
	legitFleet := newIntermediate(t, legitRoot, "Legit Fleet CA")
	deviceCA := newIntermediate(t, legitRoot, "Legit Device CA")

	// Attacker fleet — a different root/fleet the impostor relay's leaf chains to.
	evilRoot := newRoot(t)
	evilFleet := newIntermediate(t, evilRoot, "Evil Fleet CA")
	impostorLeaf := issueServerLeaf(t, evilFleet, net.IPv4(127, 0, 0, 1))

	srv := &claimServer{
		deviceCA:   deviceCA,
		fleetCAPEM: legitFleet.certPEM, // the controller vouches for the LEGIT fleet
		relaySAN:   "relay",
		caFP:       rootFingerprint(legitRoot), // and the LEGIT root — matches the link
		signingPub: make([]byte, 32),
	}
	addr := startRelay(t, srv, impostorLeaf) // but the relay presents the EVIL leaf
	srv.relayAddr = addr

	link := enroll.Link{Relay: addr, Token: "t", CAFingerprint: rootFingerprint(legitRoot)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := enroll.Claim(ctx, link, "x", "caravel"); err == nil {
		t.Fatal("Claim accepted an impostor relay whose leaf is not issued by the controller's fleet CA")
	}
}
