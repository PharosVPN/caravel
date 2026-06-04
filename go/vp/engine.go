// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package vp (virtual provider) is caravel's VPN tunnel engine. It runs an
// AmneziaWG userspace tunnel (via amnezia-vpn/amneziawg-go) over a tun device
// the platform supplies — a utun on macOS, an OS-provided fd on iOS/Android.
// XRay/REALITY will join behind the same Config/Up surface (single binary, both
// protocols).
package vp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// Obfuscation is a node's AmneziaWG obfuscation parameter set (DESIGN §3). The
// client must use the exact values the server node advertises, or the handshake
// fails. Field order matches the AmneziaWG config keys.
type Obfuscation struct {
	Jc, Jmin, Jmax     uint32
	S1, S2, S3, S4     uint32
	H1, H2, H3, H4     uint32
	I1, I2, I3, I4, I5 string
}

// Config is a resolved AmneziaWG tunnel configuration. Keys are base64 (as
// WireGuard tooling and `.pharos` profiles carry them); the engine converts
// them to the hex the UAPI wants.
type Config struct {
	PrivateKey      string   // client private key (base64)
	ServerPublicKey string   // server/node public key (base64)
	PresharedKey    string   // optional per-peer PSK (base64)
	Endpoint        string   // server host:port the client dials
	AllowedIPs      []string // routed through the tunnel; default 0.0.0.0/0 + ::/0
	Keepalive       int      // persistent keepalive seconds (0 = off)
	Obfuscation     Obfuscation
}

// Tunnel is a running AmneziaWG tunnel.
type Tunnel struct {
	dev *device.Device
}

// Up configures and brings up an AmneziaWG tunnel over tunDev. The caller owns
// the tun device (its creation, addressing, and routing) — on macOS that is a
// utun from tun.CreateTUN; on mobile it is wrapped around the fd the OS VPN
// service hands over. logLevel is one of device.LogLevel*.
func Up(cfg Config, tunDev tun.Device, logLevel int) (*Tunnel, error) {
	uapi, err := cfg.uapi()
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(logLevel, "caravel: "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("vp: configure tunnel: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("vp: bring up tunnel: %w", err)
	}
	return &Tunnel{dev: dev}, nil
}

// Close tears the tunnel down.
func (t *Tunnel) Close() error {
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	return nil
}

// Stats returns the tunnel's cumulative received/transmitted bytes, summed over
// peers, read from the AmneziaWG device's UAPI (rx_bytes / tx_bytes). ok is
// false if the device is down or stats are unavailable.
func (t *Tunnel) Stats() (rx, tx int64, ok bool) {
	if t.dev == nil {
		return 0, 0, false
	}
	s, err := t.dev.IpcGet()
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(s, "\n") {
		if v, found := strings.CutPrefix(line, "rx_bytes="); found {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				rx += n
			}
		} else if v, found := strings.CutPrefix(line, "tx_bytes="); found {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				tx += n
			}
		}
	}
	return rx, tx, true
}

// uapi renders the wireguard-go UAPI configuration string: the interface
// private key and AmneziaWG obfuscation, then the single server peer. Keys are
// emitted as hex; the obfuscation params are interface-level keys amneziawg-go
// parses (jc, jmin, jmax, s1-s4, h1-h4, i1-i5).
func (cfg Config) uapi() (string, error) {
	priv, err := keyHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("vp: private key: %w", err)
	}
	pub, err := keyHex(cfg.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("vp: server public key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)

	o := cfg.Obfuscation
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", o.Jc, o.Jmin, o.Jmax)
	fmt.Fprintf(&b, "s1=%d\ns2=%d\ns3=%d\ns4=%d\n", o.S1, o.S2, o.S3, o.S4)
	fmt.Fprintf(&b, "h1=%d\nh2=%d\nh3=%d\nh4=%d\n", o.H1, o.H2, o.H3, o.H4)
	for i, tmpl := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
		if tmpl != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, tmpl)
		}
	}

	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if cfg.PresharedKey != "" {
		psk, err := keyHex(cfg.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("vp: preshared key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	if cfg.Endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	}
	if cfg.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.Keepalive)
	}
	if len(cfg.AllowedIPs) == 0 {
		b.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
	} else {
		for _, a := range cfg.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String(), nil
}

// keyHex converts a base64-encoded 32-byte WireGuard key to lowercase hex.
func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("decode base64 key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("want a 32-byte key, got %d bytes", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
