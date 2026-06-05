// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package sync is caravel's client for coxswain's AccountSync service (DESIGN
// §8). A device reaches it through a relay: it dials the relay with its
// `.pharosid` mTLS leaf, authenticates with the account passphrase, and pulls
// its end-to-end-encrypted profile bundle — which only the device can open.
// coxswain itself never exposes the service and only ever serves ciphertext.
package sync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PharosVPN/caravel/core/crypto"
	"github.com/PharosVPN/caravel/core/deviceid"
	accountv1 "github.com/PharosVPN/caravel/core/gen/pharos/account/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// sessionMetadataKey carries the session token on authenticated RPCs — it must
// match the controller (accountsvc.sessionMetadataKey).
const sessionMetadataKey = "pharos-session"

// ErrNoProfile means the account has no profile issued yet (e.g. a freshly
// enrolled first device, before the operator issues one).
var ErrNoProfile = errors.New("sync: no profile issued for this account yet")

// Client is a connected AccountSync client, dialled through a relay with a
// device's `.pharosid` identity. Close it when done.
type Client struct {
	conn  *grpc.ClientConn
	rpc   accountv1.AccountSyncClient
	token string
}

// Dial opens an mTLS gRPC channel to the relay named in the bundle, presenting
// the device leaf. The relay authenticates the device and tunnels to coxswain's
// AccountSync; the device's TLS terminates at the relay.
func Dial(b deviceid.Bundle) (*Client, error) {
	cert, err := tls.X509KeyPair([]byte(b.DeviceCertPEM), []byte(b.DeviceKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("sync: device leaf: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.FleetCAPEM)) {
		return nil, errors.New("sync: invalid fleet CA in bundle")
	}
	tc := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   b.RelayServerName,
		MinVersion:   tls.VersionTLS13,
	})
	conn, err := grpc.NewClient(b.RelayAddr, grpc.WithTransportCredentials(tc))
	if err != nil {
		return nil, fmt.Errorf("sync: dial relay %s: %w", b.RelayAddr, err)
	}
	return &Client{conn: conn, rpc: accountv1.NewAccountSyncClient(conn)}, nil
}

// Close releases the underlying connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// authed returns ctx carrying the session token in request metadata.
func (c *Client) authed(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, sessionMetadataKey, c.token)
}

// Authenticate verifies the account passphrase and stores the session token on
// the client. It returns the user id and whether the account has enrolled keys.
func (c *Client) Authenticate(ctx context.Context, email, password string) (userID string, keysEnrolled bool, err error) {
	resp, err := c.rpc.Authenticate(ctx, &accountv1.AuthenticateRequest{Email: email, Password: password})
	if err != nil {
		return "", false, fmt.Errorf("sync: authenticate: %w", err)
	}
	c.token = resp.GetSessionToken()
	return resp.GetUserId(), resp.GetKeysEnrolled(), nil
}

// EnrollKeys registers the user's X25519 public key and a passphrase-wrapped
// private key on first-device setup. Requires a prior Authenticate.
func (c *Client) EnrollKeys(ctx context.Context, publicKey, wrappedPrivate []byte) error {
	if c.token == "" {
		return errors.New("sync: not authenticated")
	}
	_, err := c.rpc.EnrollKeys(c.authed(ctx), &accountv1.EnrollKeysRequest{
		PublicKey:         publicKey,
		WrappedPrivateKey: wrappedPrivate,
	})
	if err != nil {
		return fmt.Errorf("sync: enroll keys: %w", err)
	}
	return nil
}

// RemoteProfile is the controller's response to GetProfile: the sealed bundle
// plus what a device needs to open it (the signer's public key and the user's
// passphrase-wrapped private key).
type RemoteProfile struct {
	Ciphertext        []byte // an e2e.SealedBundle, JSON
	Revision          int64
	SigningPublicKey  []byte // controller's Ed25519 profile-signing key
	WrappedPrivateKey []byte // user's passphrase-wrapped X25519 private key
}

// GetProfile fetches the user's latest sealed profile bundle. Requires a prior
// Authenticate. Returns ErrNoProfile if the account has none yet.
func (c *Client) GetProfile(ctx context.Context) (*RemoteProfile, error) {
	if c.token == "" {
		return nil, errors.New("sync: not authenticated")
	}
	resp, err := c.rpc.GetProfile(c.authed(ctx), &accountv1.GetProfileRequest{})
	if status.Code(err) == codes.NotFound {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, fmt.Errorf("sync: get profile: %w", err)
	}
	return &RemoteProfile{
		Ciphertext:        resp.GetCiphertext(),
		Revision:          resp.GetRevision(),
		SigningPublicKey:  resp.GetSigningPublicKey(),
		WrappedPrivateKey: resp.GetWrappedPrivateKey(),
	}, nil
}

// Result is a fully-resolved sync: the decrypted plaintext profile (a
// profile.Profile JSON) plus the pieces a caller may persist to re-open the
// bundle later without the passphrase (the signer key + the unwrapped device
// key + the still-sealed bundle).
type Result struct {
	UserID       string
	Revision     int64
	Plaintext    []byte // decrypted profile JSON, ready to use/store (enc:none)
	Sealed       []byte // the original SealedBundle (for at-rest sealing)
	SignerPublic []byte // controller's Ed25519 profile-signing public key
	DeviceKey    []byte // the user's unwrapped X25519 private key
}

// Fetch runs the whole device-side sync: dial → authenticate → (enroll on a
// first device) → get the sealed bundle → unwrap the device key with the
// passphrase → open the bundle. It returns the decrypted profile. The controller
// only ever handled ciphertext.
func Fetch(ctx context.Context, b deviceid.Bundle, email, password string) (*Result, error) {
	c, err := Dial(b)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	userID, keysEnrolled, err := c.Authenticate(ctx, email, password)
	if err != nil {
		return nil, err
	}

	// First device for this account: mint the user's keypair, wrap the private
	// key under the passphrase, and enrol the public key + wrapped blob.
	if !keysEnrolled {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		wrapped, err := crypto.WrapPrivateKey(password, kp.Private)
		if err != nil {
			return nil, err
		}
		if err := c.EnrollKeys(ctx, kp.Public, wrapped); err != nil {
			return nil, err
		}
	}

	rp, err := c.GetProfile(ctx)
	if err != nil {
		return nil, err
	}

	deviceKey, err := crypto.UnwrapPrivateKey(password, rp.WrappedPrivateKey)
	if err != nil {
		return nil, err
	}
	var bundle crypto.SealedBundle
	if err := json.Unmarshal(rp.Ciphertext, &bundle); err != nil {
		return nil, fmt.Errorf("sync: malformed sealed bundle: %w", err)
	}
	plaintext, err := crypto.OpenSealed(bundle, deviceKey, rp.SigningPublicKey)
	if err != nil {
		return nil, err
	}
	return &Result{
		UserID:       userID,
		Revision:     rp.Revision,
		Plaintext:    plaintext,
		Sealed:       rp.Ciphertext,
		SignerPublic: rp.SigningPublicKey,
		DeviceKey:    deviceKey,
	}, nil
}
