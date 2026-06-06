// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package profile reads the `.pharos` profile file (DESIGN §9) and resolves a
// node's AmneziaWG parameters into a dialable tunnel. The on-disk format mirrors
// the controller's internal/pharos + internal/profile exactly: a JSON envelope
// with an always-readable header (`fmt`/`v`/`enc`) and a payload that is
// plaintext, password-encrypted, or sealed to a user account.
package profile

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/PharosVPN/caravel/core/crypto"
)

// Format constants — must match the controller (internal/pharos).
const (
	formatTag     = "pharos-profile"
	formatVersion = 1

	// Extension and MIMEType identify the file to the OS / import handlers.
	Extension = ".pharos"
	MIMEType  = "application/vnd.pharosvpn.profile"

	EncNone     = "none"
	EncPassword = "password"
	EncAccount  = "account"

	// Protocol type tags (must match the controller's internal/profile).
	ProtocolAmneziaWG   = "amneziawg"
	ProtocolXRayReality = "xray-reality"

	// defaultClientPort is where a node's client interface (awg0) listens when a
	// profile's endpoint pool carries no explicit port (controller awgClientPort).
	defaultClientPort = 443
	// Sensible client-side tunnel defaults (the profile carries neither).
	defaultKeepalive = 25
	defaultMTU       = 1420
)

// Parse errors.
var (
	ErrNotPharos        = errors.New("profile: not a pharos-profile file")
	ErrUnsupportedVer   = errors.New("profile: unsupported profile version")
	ErrPasswordNeeded   = errors.New("profile: password-protected profile — a password is required")
	ErrAccountKeyNeeded = errors.New("profile: account-mode profile — a device key + signer key are required")
	ErrNoAmneziaWG      = errors.New("profile: node has no AmneziaWG protocol")
	ErrNoXRayReality    = errors.New("profile: node has no XRay/REALITY protocol")
	ErrNoNode           = errors.New("profile: profile has no usable node")
	ErrNoProfile        = errors.New("profile: bundle has no matching profile")
)

// kdfParams records password-mode key-derivation parameters (pharos.kdfParams).
type kdfParams struct {
	Algo    string `json:"algo"`
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
}

// envelope is the on-disk `.pharos` container (pharos.envelope). Field order and
// tags match the controller so the password-mode AAD is byte-identical.
type envelope struct {
	Fmt     string          `json:"fmt"`
	V       int             `json:"v"`
	Enc     string          `json:"enc"`
	KDF     *kdfParams      `json:"kdf,omitempty"`
	Nonce   []byte          `json:"nonce,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// aad returns the authenticated header bytes — the envelope with the payload
// cleared (pharos.envelope.aad), so enc/v/KDF cannot be downgraded.
func (e envelope) aad() ([]byte, error) {
	h := e
	h.Payload = nil
	return json.Marshal(h)
}

// Options carries the secrets needed to open encrypted profiles.
type Options struct {
	Password     string            // password mode
	DeviceKey    []byte            // account mode: the user's X25519 private key
	SignerPublic ed25519.PublicKey // account mode: the controller's profile-signing public key
}

// Profile is a parsed .pharos bundle (internal/profile.Profile): the set of
// named profiles a device holds.
type Profile struct {
	FleetID   string          `json:"fleet_id"`
	User      string          `json:"user"`
	Revision  int64           `json:"revision"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Profiles  []ClientProfile `json:"profiles"`
}

// ClientProfile is one named connection config in a bundle (internal/profile.
// ClientProfile): a single data-plane protocol, the entry node(s) to dial, and —
// for a cascade profile — the egress chain. The app lists these by name and the
// user connects with one.
type ClientProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Nodes    []Node `json:"nodes"`
	// Path is the egress chain (entry → [mid] → exit) for a cascade profile; nil
	// for a direct single-node egress. The client dials the entry hop and the
	// controller routes the rest server-side.
	Path *PathView `json:"path,omitempty"`
}

// PathHop is one node in a profile's egress chain (hop 0 = entry, last = exit).
type PathHop struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Role   string   `json:"role"`
	IPs    []string `json:"ips"`
}

// PathView is the ordered egress chain a cascade profile's traffic takes.
type PathView struct {
	Name string    `json:"name"`
	Hops []PathHop `json:"hops"`
}

// Select returns the profile matching ref (by id or name), or the first profile
// when ref is empty. ErrNoProfile if there are none or no match.
func (p *Profile) Select(ref string) (*ClientProfile, error) {
	if len(p.Profiles) == 0 {
		return nil, ErrNoProfile
	}
	if ref == "" {
		return &p.Profiles[0], nil
	}
	for i := range p.Profiles {
		if p.Profiles[i].ID == ref || p.Profiles[i].Name == ref {
			return &p.Profiles[i], nil
		}
	}
	return nil, ErrNoProfile
}

// SelectByProtocol returns the first profile carrying the given data-plane
// protocol, or ErrNoProfile if none does.
func (p *Profile) SelectByProtocol(proto string) (*ClientProfile, error) {
	for i := range p.Profiles {
		if p.Profiles[i].Protocol == proto {
			return &p.Profiles[i], nil
		}
	}
	return nil, ErrNoProfile
}

// Names lists the profile names in the bundle, for display.
func (p *Profile) Names() []string {
	out := make([]string, len(p.Profiles))
	for i, cp := range p.Profiles {
		out[i] = cp.Name
	}
	return out
}

// EntryNodeID is the node id of the profile's cascade entry hop, or "" if the
// profile has no egress path. A cascade profile must enter at this node.
func (cp *ClientProfile) EntryNodeID() string {
	if cp.Path == nil {
		return ""
	}
	for _, h := range cp.Path.Hops {
		if h.Role == "entry" {
			return h.ID
		}
	}
	if len(cp.Path.Hops) > 0 {
		return cp.Path.Hops[0].ID
	}
	return ""
}

// Node is one VPN endpoint in a profile.
type Node struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Region    string     `json:"region"`
	Endpoints []string   `json:"endpoints"`
	Protocols []Protocol `json:"protocols"`
}

// Protocol is a versioned, tagged protocol entry (ignore-unknown by type).
type Protocol struct {
	Type   string          `json:"type"`
	V      int             `json:"v"`
	Params json.RawMessage `json:"params"`
}

// AmneziaWG is the params for a `type:"amneziawg"` protocol (profile.build).
type AmneziaWG struct {
	PrivateKey   string         `json:"private_key"`
	Address      string         `json:"address"`
	PublicKey    string         `json:"public_key"`
	PresharedKey string         `json:"preshared_key"`
	Endpoints    []EndpointPool `json:"endpoints"`
	AllowedIPs   []string       `json:"allowed_ips"`
	Obfuscation  Obfuscation    `json:"obfuscation"`
}

// EndpointPool is one entry-point IP and its rotatable port range (decision 17).
type EndpointPool struct {
	IP      string `json:"ip"`
	PortMin int    `json:"port_min"`
	PortMax int    `json:"port_max"`
}

// Obfuscation is the AmneziaWG obfuscation set (wg.Obfuscation).
type Obfuscation struct {
	Jc   uint32 `json:"jc"`
	Jmin uint32 `json:"jmin"`
	Jmax uint32 `json:"jmax"`
	S1   uint32 `json:"s1"`
	S2   uint32 `json:"s2"`
	S3   uint32 `json:"s3"`
	S4   uint32 `json:"s4"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
}

// XRayReality is the params for a `type:"xray-reality"` protocol (profile.build).
// The node owns its REALITY keypair; the client gets the public key plus its own
// VLESS identity (UUID + flow) and the camouflage policy it must present.
type XRayReality struct {
	UUID        string         `json:"uuid"`
	Flow        string         `json:"flow"`
	Address     string         `json:"address"`
	PublicKey   string         `json:"public_key"`  // node's REALITY public key
	ServerName  string         `json:"server_name"` // SNI the client presents (decoy host)
	ShortID     string         `json:"short_id"`
	Fingerprint string         `json:"fingerprint"` // uTLS fingerprint, e.g. "chrome"
	Endpoints   []EndpointPool `json:"endpoints"`
	AllowedIPs  []string       `json:"allowed_ips"`
}

// Tunnel is a resolved, dialable AmneziaWG tunnel for one node — everything the
// platform shell needs (vp.Config fields + the utun address).
type Tunnel struct {
	NodeID          string
	NodeName        string
	PrivateKey      string
	ServerPublicKey string
	PresharedKey    string
	Endpoint        string // host:port to dial
	Address         string // bare tunnel IP for the utun (CIDR mask stripped)
	AllowedIPs      []string
	Keepalive       int
	MTU             int
	Obfuscation     Obfuscation
}

// XRayTunnel is a resolved, dialable XRay/REALITY tunnel for one node —
// everything the platform shell / engine needs to stand up a VLESS+REALITY
// outbound and route the utun through it.
type XRayTunnel struct {
	NodeID      string
	NodeName    string
	UUID        string // VLESS client id
	Flow        string // VLESS flow, e.g. "xtls-rprx-vision"
	Endpoint    string // host:port to dial (TCP)
	Address     string // bare tunnel IP for the utun (CIDR mask stripped)
	PublicKey   string // node's REALITY public key
	ServerName  string // SNI to present (decoy host)
	ShortID     string
	Fingerprint string // uTLS fingerprint, e.g. "chrome"
	AllowedIPs  []string
	MTU         int
}

// Parse decodes a `.pharos` file, decrypting per its `enc` mode. It content-
// sniffs the `fmt` header so renamed files still import.
func Parse(data []byte, opts Options) (*Profile, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil || env.Fmt != formatTag {
		return nil, ErrNotPharos
	}
	if env.V != formatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVer, env.V)
	}

	var plaintext []byte
	switch env.Enc {
	case EncNone:
		plaintext = env.Payload
	case EncPassword:
		pt, err := openPassword(env, opts.Password)
		if err != nil {
			return nil, err
		}
		plaintext = pt
	case EncAccount:
		if len(opts.DeviceKey) == 0 || len(opts.SignerPublic) == 0 {
			return nil, ErrAccountKeyNeeded
		}
		var bundle crypto.SealedBundle
		if err := json.Unmarshal(env.Payload, &bundle); err != nil {
			return nil, ErrNotPharos
		}
		pt, err := crypto.OpenSealed(bundle, opts.DeviceKey, opts.SignerPublic)
		if err != nil {
			return nil, err
		}
		plaintext = pt
	default:
		return nil, fmt.Errorf("profile: unknown enc mode %q", env.Enc)
	}

	var p Profile
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("profile: decode payload: %w", err)
	}
	return &p, nil
}

// openPassword derives the key (Argon2id from the file's kdf header) and opens
// the XChaCha20-Poly1305 payload, authenticating the header as AAD.
func openPassword(env envelope, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrPasswordNeeded
	}
	if env.KDF == nil {
		return nil, ErrNotPharos
	}
	var ciphertext []byte
	if err := json.Unmarshal(env.Payload, &ciphertext); err != nil {
		return nil, ErrNotPharos
	}
	aad, err := env.aad()
	if err != nil {
		return nil, err
	}
	key := crypto.DeriveKEK(password, env.KDF.Salt, env.KDF.Time, env.KDF.Memory, env.KDF.Threads)
	return crypto.OpenXChaCha(key, env.Nonce, ciphertext, aad)
}

// Node returns a node in the profile by id, or the first node when id is empty.
// ErrNoNode if there are none / no match.
func (cp *ClientProfile) Node(id string) (*Node, error) {
	// With no explicit choice, a cascade profile must enter at its entry hop —
	// dialing a different node would bypass the cascade.
	if id == "" {
		if entry := cp.EntryNodeID(); entry != "" {
			for i := range cp.Nodes {
				if cp.Nodes[i].ID == entry {
					return &cp.Nodes[i], nil
				}
			}
		}
	}
	for i := range cp.Nodes {
		if id == "" || cp.Nodes[i].ID == id || cp.Nodes[i].Name == id {
			return &cp.Nodes[i], nil
		}
	}
	return nil, ErrNoNode
}

// HasXRayReality reports whether the node offers an XRay/REALITY protocol entry.
func (n *Node) HasXRayReality() bool {
	for _, pr := range n.Protocols {
		if pr.Type == "xray-reality" {
			return true
		}
	}
	return false
}

// amneziaWG returns the node's AmneziaWG params, ignoring unknown protocols.
func (n *Node) amneziaWG() (*AmneziaWG, error) {
	for _, pr := range n.Protocols {
		if pr.Type == "amneziawg" {
			var a AmneziaWG
			if err := json.Unmarshal(pr.Params, &a); err != nil {
				return nil, fmt.Errorf("profile: decode amneziawg params: %w", err)
			}
			return &a, nil
		}
	}
	return nil, ErrNoAmneziaWG
}

// xrayReality returns the node's XRay/REALITY params, ignoring unknown protocols.
func (n *Node) xrayReality() (*XRayReality, error) {
	for _, pr := range n.Protocols {
		if pr.Type == "xray-reality" {
			var x XRayReality
			if err := json.Unmarshal(pr.Params, &x); err != nil {
				return nil, fmt.Errorf("profile: decode xray-reality params: %w", err)
			}
			return &x, nil
		}
	}
	return nil, ErrNoXRayReality
}

// Tunnel resolves the node's AmneziaWG protocol into a dialable Tunnel: it picks
// an entry endpoint from the pool (or the node's IP list) and strips the address
// CIDR for the utun.
func (n *Node) Tunnel() (*Tunnel, error) {
	a, err := n.amneziaWG()
	if err != nil {
		return nil, err
	}
	endpoint, err := a.dialEndpoint(n.Endpoints)
	if err != nil {
		return nil, err
	}
	allowed := a.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	return &Tunnel{
		NodeID:          n.ID,
		NodeName:        n.Name,
		PrivateKey:      a.PrivateKey,
		ServerPublicKey: a.PublicKey,
		PresharedKey:    a.PresharedKey,
		Endpoint:        endpoint,
		Address:         bareIP(a.Address),
		AllowedIPs:      allowed,
		Keepalive:       defaultKeepalive,
		MTU:             defaultMTU,
		Obfuscation:     a.Obfuscation,
	}, nil
}

// XRayTunnel resolves the node's XRay/REALITY protocol into a dialable
// XRayTunnel: it picks an entry endpoint (TCP) from the pool (or the node's IP
// list) and strips the address CIDR for the utun.
func (n *Node) XRayTunnel() (*XRayTunnel, error) {
	x, err := n.xrayReality()
	if err != nil {
		return nil, err
	}
	endpoint, err := pickEndpoint(x.Endpoints, n.Endpoints)
	if err != nil {
		return nil, err
	}
	allowed := x.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	flow := x.Flow
	fingerprint := x.Fingerprint
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	return &XRayTunnel{
		NodeID:      n.ID,
		NodeName:    n.Name,
		UUID:        x.UUID,
		Flow:        flow,
		Endpoint:    endpoint,
		Address:     bareIP(x.Address),
		PublicKey:   x.PublicKey,
		ServerName:  x.ServerName,
		ShortID:     x.ShortID,
		Fingerprint: fingerprint,
		AllowedIPs:  allowed,
		MTU:         defaultMTU,
	}, nil
}

// dialEndpoint picks a host:port to dial at RANDOM from the node's endpoint pool
// — a random IP and a random port in that entry's [PortMin, PortMax] range
// (decision 17). The entry point therefore varies every connect, so there is no
// single fixed IP/port to fingerprint or block. Falls back to a random IP from
// the node's flat list at the default port when no pool is present.
func (a *AmneziaWG) dialEndpoint(fallbackIPs []string) (string, error) {
	return pickEndpoint(a.Endpoints, fallbackIPs)
}

// pickEndpoint picks a host:port to dial at RANDOM from an endpoint pool — a
// random IP and a random port in that entry's [PortMin, PortMax] range (decision
// 17), so the entry point varies every connect and there is no single fixed
// IP/port to fingerprint or block. Falls back to a random IP from the node's
// flat list at the default port when no pool is present. Shared by AmneziaWG
// (UDP) and XRay/REALITY (TCP) — the transport is the caller's concern.
func pickEndpoint(endpoints []EndpointPool, fallbackIPs []string) (string, error) {
	pool := make([]EndpointPool, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.IP != "" {
			pool = append(pool, ep)
		}
	}
	if len(pool) > 0 {
		ep := pool[rand.IntN(len(pool))]
		return net.JoinHostPort(ep.IP, strconv.Itoa(randPort(ep.PortMin, ep.PortMax))), nil
	}
	ips := make([]string, 0, len(fallbackIPs))
	for _, ip := range fallbackIPs {
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	if len(ips) > 0 {
		return net.JoinHostPort(ips[rand.IntN(len(ips))], strconv.Itoa(defaultClientPort)), nil
	}
	return "", errors.New("profile: node has no endpoint to dial")
}

// randPort returns a random UDP port in [min, max]; an unset min defaults to the
// client port, and a zero-width / invalid range collapses to the single port.
func randPort(min, max int) int {
	if min <= 0 {
		min = defaultClientPort
	}
	if max <= min {
		return min
	}
	return min + rand.IntN(max-min+1)
}

// bareIP strips a CIDR mask from an address ("10.86.0.5/32" → "10.86.0.5").
func bareIP(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}
