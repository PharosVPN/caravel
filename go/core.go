// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package core is caravel's gomobile-bound engine for the native mobile clients
// (caravel-android, caravel-ios). It is the library form of the caravel-mac
// worker: a profile store, account sync (replace-all), controller status, and a
// connect path that runs the AmneziaWG / XRay engine over the TUN file
// descriptor the OS VPN service provides. Complex values cross the gomobile
// boundary as JSON strings; the platform owns the UI, the secure passphrase
// store, and the TUN lifecycle. See docs/cloud-sync.md for the UX contract.
package core

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PharosVPN/caravel/core/deviceid"
	"github.com/PharosVPN/caravel/core/profile"
	csync "github.com/PharosVPN/caravel/core/sync"
	"github.com/PharosVPN/caravel/core/vp"
	awgtun "github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/unix"
)

//go:embed VERSION
var versionFile string

// Version returns the caravel core version.
func Version() string { return strings.TrimSpace(versionFile) }

// logLevelError is amneziawg-go's device.LogLevelError (errors only).
const logLevelError = 1

// store is the on-disk profile store; set by Init.
var store *profile.Store

// Init points the engine at the app's profile directory (e.g. the Android
// filesDir or the iOS App Group container). Call once at startup.
func Init(dir string) error {
	s, err := profile.NewStore(dir)
	if err != nil {
		return err
	}
	store = s
	return nil
}

func ensureStore() error {
	if store == nil {
		return errors.New("core: not initialized — call Init(dir) first")
	}
	return nil
}

// syncedPath / pidPath build sidecar paths next to <name>.pharos.
func syncedPath(name string) string { return filepath.Join(store.Dir(), name+".synced") }
func pidPath(name string) string    { return filepath.Join(store.Dir(), name+deviceid.Extension) }

func isCloud(name string) bool {
	_, err := os.Stat(syncedPath(name))
	return err == nil
}

// ImportBundle copies a `.pharos` file into the store and returns its name.
func ImportBundle(path string) (string, error) {
	if err := ensureStore(); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	name := sanitizeName(strings.TrimSuffix(filepath.Base(path), profile.Extension))
	if _, err := store.Import(name, data); err != nil {
		return "", err
	}
	return name, nil
}

// SyncAndStore logs in / re-syncs: it fetches the account's sealed bundle through
// the relay named in the `.pharosid`, decrypts it on-device, REPLACES the whole
// cloud-synced set, and stores the fresh bundle + a `.synced` marker + the
// `.pharosid`. email may be "" (the device leaf authenticates). Returns the
// stored bundle name. The passphrase is the platform's to keep (keystore).
func SyncAndStore(pharosid []byte, email, password string) (string, error) {
	if err := ensureStore(); err != nil {
		return "", err
	}
	bundle, err := deviceid.Parse(pharosid)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	res, err := csync.Fetch(ctx, bundle, email, password)
	if err != nil {
		return "", err
	}

	purgeCloud() // replace-all: drop the prior cloud set first

	env, err := profile.WrapPlaintext(res.Plaintext)
	if err != nil {
		return "", err
	}
	name := sanitizeName(firstNonEmpty(bundle.Alias, email, "account"))
	if _, err := store.Import(name, env); err != nil {
		return "", err
	}
	marker, _ := json.Marshal(map[string]any{
		"user": email, "revision": res.Revision,
		"relay": bundle.RelayAddr, "controller": bundle.CAFingerprint,
		"synced_at": time.Now().UTC().Format(time.RFC3339),
	})
	_ = os.WriteFile(syncedPath(name), marker, 0o600)
	_ = os.WriteFile(pidPath(name), pharosid, 0o600)
	return name, nil
}

// purgeCloud removes every cloud-synced bundle (a `.synced` marker) + sidecars.
// Imported profiles (no marker) are kept. Mirrors caravel-mac purgeCloudProfiles.
func purgeCloud() int {
	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".synced") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".synced")
		for _, suf := range []string{profile.Extension, ".synced", ".disabled", deviceid.Extension} {
			_ = os.Remove(filepath.Join(store.Dir(), base+suf))
		}
		n++
	}
	return n
}

// Logout removes all cloud-synced profiles; returns the count. (The platform
// also clears the stored passphrase.)
func Logout() int {
	if ensureStore() != nil {
		return 0
	}
	return purgeCloud()
}

// jsonProfile is one selectable named profile, flattened across bundles.
type jsonProfile struct {
	Bundle      string                   `json:"bundle"`
	Name        string                   `json:"name"`
	Protocol    string                   `json:"protocol"`
	Nodes       []jsonNode               `json:"nodes"`
	Path        *profile.PathView        `json:"path,omitempty"`
	Control     *profile.ControlEndpoint `json:"control,omitempty"`
	CloudSynced bool                     `json:"cloud_synced"`
}

type jsonNode struct {
	Name   string   `json:"name"`
	Region string   `json:"region"`
	IPs    []string `json:"ips"`
}

// ListProfiles returns the store flattened to one entry per named profile, as
// JSON — what the client lists and connects with.
func ListProfiles() string {
	if ensureStore() != nil {
		return "[]"
	}
	entries, _ := store.List()
	out := []jsonProfile{}
	for _, e := range entries {
		data, err := store.Raw(e.Name)
		if err != nil {
			continue
		}
		p, err := profile.Parse(data, profile.Options{})
		if err != nil {
			continue
		}
		cloud := isCloud(e.Name)
		for i := range p.Profiles {
			cp := &p.Profiles[i]
			nodes := make([]jsonNode, 0, len(cp.Nodes))
			for _, n := range cp.Nodes {
				nodes = append(nodes, jsonNode{Name: n.Name, Region: n.Region, IPs: n.Endpoints})
			}
			out = append(out, jsonProfile{
				Bundle: e.Name, Name: cp.Name, Protocol: cp.Protocol,
				Nodes: nodes, Path: cp.Path, Control: p.Control, CloudSynced: cloud,
			})
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// ControllerStatus returns JSON {reachable,last_synced_at,relay,controller} for
// a bundle — the cloud session's liveness (reachable is informational).
func ControllerStatus(bundleName string) string {
	type ctlStatus struct {
		Reachable    bool                     `json:"reachable"`
		LastSyncedAt string                   `json:"last_synced_at,omitempty"`
		Relay        string                   `json:"relay,omitempty"`
		Controller   *profile.ControlEndpoint `json:"controller,omitempty"`
	}
	var s ctlStatus
	if ensureStore() != nil {
		b, _ := json.Marshal(s)
		return string(b)
	}
	if data, err := store.Raw(bundleName); err == nil {
		if p, perr := profile.Parse(data, profile.Options{}); perr == nil {
			s.Controller = p.Control
		}
	}
	if mb, err := os.ReadFile(syncedPath(bundleName)); err == nil {
		var m struct {
			Relay    string `json:"relay"`
			SyncedAt string `json:"synced_at"`
		}
		_ = json.Unmarshal(mb, &m)
		s.Relay, s.LastSyncedAt = m.Relay, m.SyncedAt
	}
	if pid, err := os.ReadFile(pidPath(bundleName)); err == nil {
		if b, berr := deviceid.Parse(pid); berr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			s.Reachable = csync.Reachable(ctx, b, 5*time.Second)
		}
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// Reachable probes the relay named in a raw `.pharosid` (a TLS dial). Informational.
func Reachable(pharosid []byte, timeoutMs int) bool {
	b, err := deviceid.Parse(pharosid)
	if err != nil {
		return false
	}
	d := time.Duration(timeoutMs) * time.Millisecond
	if d <= 0 {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return csync.Reachable(ctx, b, d)
}

// resolve picks the named profile and the entry node, and decides which protocol
// to dial — for a "both" profile, protoPref ("auto"|"amneziawg"|"xray") chooses
// (auto/"" → AmneziaWG, the default).
func resolve(bundleName, profileName, protoPref string) (*profile.ClientProfile, *profile.Node, bool, error) {
	if err := ensureStore(); err != nil {
		return nil, nil, false, err
	}
	data, err := store.Raw(bundleName)
	if err != nil {
		return nil, nil, false, err
	}
	p, err := profile.Parse(data, profile.Options{})
	if err != nil {
		return nil, nil, false, err
	}
	cp, err := p.Select(profileName)
	if err != nil {
		return nil, nil, false, err
	}
	node, err := cp.Node("")
	if err != nil {
		return nil, nil, false, err
	}
	useXRay := cp.Protocol == profile.ProtocolXRayReality
	if cp.Protocol == profile.ProtocolBoth {
		useXRay = protoPref == "xray" || protoPref == profile.ProtocolXRayReality
	}
	return cp, node, useXRay, nil
}

// Prepare returns the network parameters the platform needs to build the TUN for
// a profile (address, mtu, dns, routes, endpoint, proto), as JSON. Call it before
// establishing the OS tunnel, then pass the resulting fd to Connect.
func Prepare(bundleName, profileName, protoPref string) (string, error) {
	_, node, useXRay, err := resolve(bundleName, profileName, protoPref)
	if err != nil {
		return "", err
	}
	type netParams struct {
		Address  string   `json:"address"`
		MTU      int      `json:"mtu"`
		DNS      []string `json:"dns"`
		Routes   []string `json:"routes"`
		Endpoint string   `json:"endpoint"`
		Proto    string   `json:"proto"`
	}
	np := netParams{DNS: []string{"1.1.1.1"}, MTU: 1420}
	if useXRay {
		xt, err := node.XRayTunnel()
		if err != nil {
			return "", err
		}
		np.Address, np.Routes, np.Endpoint, np.Proto = xt.Address, xt.AllowedIPs, xt.Endpoint, profile.ProtocolXRayReality
		if xt.MTU > 0 {
			np.MTU = xt.MTU
		}
	} else {
		t, err := node.Tunnel()
		if err != nil {
			return "", err
		}
		np.Address, np.Routes, np.Endpoint, np.Proto = t.Address, t.AllowedIPs, t.Endpoint, profile.ProtocolAmneziaWG
		if t.MTU > 0 {
			np.MTU = t.MTU
		}
	}
	if len(np.Routes) == 0 {
		np.Routes = []string{"0.0.0.0/0", "::/0"}
	}
	b, _ := json.Marshal(np)
	return string(b), nil
}

// Session is a running tunnel (either AmneziaWG or XRay/REALITY).
type Session struct {
	awg      *vp.Tunnel
	xray     *vp.XRayTunnel
	proto    string
	endpoint string
}

// Connect runs the tunnel engine over the platform-provided TUN file descriptor
// (from VpnService.establish / NEPacketTunnelProvider). The fd is dup'd so the
// engine owns its copy; Stop closes it. Call Prepare first to configure the TUN.
func Connect(bundleName, profileName, protoPref string, tunFd int) (*Session, error) {
	_, node, useXRay, err := resolve(bundleName, profileName, protoPref)
	if err != nil {
		return nil, err
	}
	dfd, err := unix.Dup(tunFd)
	if err != nil {
		return nil, fmt.Errorf("core: dup tun fd: %w", err)
	}

	if useXRay {
		xt, err := node.XRayTunnel()
		if err != nil {
			_ = unix.Close(dfd)
			return nil, err
		}
		mtu := xt.MTU
		if mtu <= 0 {
			mtu = 1420
		}
		dev, err := awgtun.CreateTUNFromFile(os.NewFile(uintptr(dfd), "tun"), mtu)
		if err != nil {
			return nil, fmt.Errorf("core: tun from fd: %w", err)
		}
		t, err := vp.UpXRay(vp.XRayConfig{
			UUID: xt.UUID, Flow: xt.Flow, Endpoint: xt.Endpoint, PublicKey: xt.PublicKey,
			ServerName: xt.ServerName, ShortID: xt.ShortID, Fingerprint: xt.Fingerprint,
			AllowedIPs: xt.AllowedIPs, MTU: mtu,
		}, dev)
		if err != nil {
			_ = dev.Close()
			return nil, err
		}
		return &Session{xray: t, proto: profile.ProtocolXRayReality, endpoint: xt.Endpoint}, nil
	}

	t, err := node.Tunnel()
	if err != nil {
		_ = unix.Close(dfd)
		return nil, err
	}
	mtu := t.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	dev, err := awgtun.CreateTUNFromFile(os.NewFile(uintptr(dfd), "tun"), mtu)
	if err != nil {
		return nil, fmt.Errorf("core: tun from fd: %w", err)
	}
	tun, err := vp.Up(vp.Config{
		PrivateKey: t.PrivateKey, ServerPublicKey: t.ServerPublicKey, PresharedKey: t.PresharedKey,
		Endpoint: t.Endpoint, AllowedIPs: t.AllowedIPs, Keepalive: t.Keepalive,
		Obfuscation: toVPObfuscation(t.Obfuscation),
	}, dev, logLevelError)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return &Session{awg: tun, proto: profile.ProtocolAmneziaWG, endpoint: t.Endpoint}, nil
}

// Stats returns JSON {rx,tx,proto,endpoint} for the live tunnel.
func (s *Session) Stats() string {
	var rx, tx int64
	if s.awg != nil {
		rx, tx, _ = s.awg.Stats()
	} else if s.xray != nil {
		rx, tx, _ = s.xray.Stats()
	}
	b, _ := json.Marshal(map[string]any{"rx": rx, "tx": tx, "proto": s.proto, "endpoint": s.endpoint})
	return string(b)
}

// Stop tears the tunnel down (and closes the dup'd TUN fd).
func (s *Session) Stop() {
	if s.awg != nil {
		_ = s.awg.Close()
		s.awg = nil
	}
	if s.xray != nil {
		_ = s.xray.Close()
		s.xray = nil
	}
}

// toVPObfuscation maps a profile's obfuscation set to the engine's.
func toVPObfuscation(o profile.Obfuscation) vp.Obfuscation {
	return vp.Obfuscation{
		Jc: o.Jc, Jmin: o.Jmin, Jmax: o.Jmax,
		S1: o.S1, S2: o.S2, S3: o.S3, S4: o.S4,
		H1: o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
		I1: o.I1, I2: o.I2, I3: o.I3, I4: o.I4, I5: o.I5,
	}
}

// sanitizeName makes a filesystem-safe store name.
func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', ' ':
			return '-'
		}
		return r
	}, s)
	if s == "" {
		return "profile"
	}
	return s
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
