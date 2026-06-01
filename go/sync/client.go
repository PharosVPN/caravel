// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package sync is the gRPC client for coxswain's AccountSync service.
// Caravel reaches it through a beacon relay (DESIGN §6, §8).
package sync

import "context"

// Client dials coxswain's AccountSync service through a beacon relay.
type Client struct {
	relayAddr string // e.g., "beacon.example.com:443"
}

// NewClient creates a new sync client.
// relayAddr is the beacon relay's public address.
func NewClient(relayAddr string) *Client {
	return &Client{relayAddr: relayAddr}
}

// Authenticate logs in a user and returns a session token.
func (c *Client) Authenticate(ctx context.Context, email, password string) (string, error) {
	// TODO: call pharos.account.v1.AccountSync/Authenticate gRPC
	// Returns sessionToken (JWT)
	return "", nil
}

// GetProfile fetches the user's encrypted profile bundle.
func (c *Client) GetProfile(ctx context.Context, deviceID string, sessionToken string) ([]byte, error) {
	// TODO: call pharos.account.v1.AccountSync/GetProfile gRPC
	// Returns E2E-encrypted profile (ciphertext)
	return nil, nil
}

// EnrollKeys creates a new device keypair and enrolls it with coxswain.
func (c *Client) EnrollKeys(ctx context.Context, sessionToken string) (publicKey string, err error) {
	// TODO: Ed25519 keygen on-device
	// TODO: call pharos.account.v1.AccountSync/EnrollKeys gRPC with public key
	// Returns device-bound cert
	return "", nil
}
