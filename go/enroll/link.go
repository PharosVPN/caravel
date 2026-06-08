// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package enroll is caravel's device-side join-link enrollment: it redeems a
// `pharosvpn://enroll` deep link (from a QR or a pasted URL) into a fully
// enrolled, passphrase-less device. The device generates its own keys, claims a
// one-time ticket through the relay (cert-less, the only AccountSync method that
// needs no device leaf — this RPC mints it), and assembles its `.pharosid` from
// the response. It is the executable counterpart of helm's internal/enroll
// (which issues the ticket + renders the QR).
package enroll

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Scheme / host of the enrollment deep link (helm enroll.TicketURL).
const (
	linkScheme = "pharosvpn"
	linkHost   = "enroll"
)

// Link is a parsed `pharosvpn://enroll?relay=<host:port>&token=<token>&ca=<root_ca_fingerprint>`
// deep link — everything a device needs to start a claim.
type Link struct {
	// Relay is the public relay endpoint (host:port) the device claims through and
	// later syncs through.
	Relay string
	// Token is the one-time enrollment ticket; the sole credential of the claim.
	Token string
	// CAFingerprint is the root CA fingerprint (lowercase hex SHA-256 of the root
	// CA DER) the device pins. It must equal the controller's own ca_fingerprint
	// in the claim response.
	CAFingerprint string
}

// ParseLink decodes a `pharosvpn://enroll?...` deep link. It rejects a wrong
// scheme/host or a link missing any of relay/token/ca.
func ParseLink(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Link{}, errors.New("enroll: empty link")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Link{}, fmt.Errorf("enroll: parse link: %w", err)
	}
	if u.Scheme != linkScheme {
		return Link{}, fmt.Errorf("enroll: not a %s:// link", linkScheme)
	}
	// pharosvpn://enroll?... parses "enroll" as the host.
	if u.Host != linkHost {
		return Link{}, fmt.Errorf("enroll: not an %s link (host %q)", linkHost, u.Host)
	}
	q := u.Query()
	l := Link{
		Relay:         strings.TrimSpace(q.Get("relay")),
		Token:         strings.TrimSpace(q.Get("token")),
		CAFingerprint: strings.TrimSpace(q.Get("ca")),
	}
	switch {
	case l.Relay == "":
		return Link{}, errors.New("enroll: link missing relay")
	case l.Token == "":
		return Link{}, errors.New("enroll: link missing token")
	case l.CAFingerprint == "":
		return Link{}, errors.New("enroll: link missing ca fingerprint")
	}
	return l, nil
}
