// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// distro/all registers every xray protocol/transport (VLESS, REALITY,
	// freedom, socks, …) so a JSON config can reference them. Pulls the full
	// xray-core; the binary stays a single CGO-free static build.
	_ "github.com/xtls/xray-core/main/distro/all"
)

// defaultXRayFingerprint is the uTLS fingerprint the REALITY client mimics when
// the profile carries none.
const defaultXRayFingerprint = "chrome"

// defaultTunMTU sizes the netstack + tun buffers when the config carries no MTU.
const defaultTunMTU = 1500

// XRayConfig is a resolved XRay/REALITY client configuration — everything the
// engine needs to stand up a VLESS+REALITY outbound to one node. It is the
// XRay counterpart of Config (AmneziaWG); the platform shell builds it from the
// profile's XRayTunnel.
type XRayConfig struct {
	UUID        string   // VLESS client id
	Flow        string   // VLESS flow, e.g. "xtls-rprx-vision" ("" = none)
	Endpoint    string   // node host:port to dial (TCP, REALITY)
	PublicKey   string   // node's REALITY public key (base64url)
	ServerName  string   // SNI the client presents (the decoy host)
	ShortID     string   // REALITY shortId (may be empty)
	Fingerprint string   // uTLS fingerprint, e.g. "chrome" ("" = chrome)
	AllowedIPs  []string // routed through the tunnel (the tun owner enforces routing)
	MTU         int      // tun MTU (0 = default)
}

// XRayTunnel is a running XRay/REALITY tunnel: an embedded xray-core client
// (SOCKS inbound + VLESS/REALITY outbound) plus a gVisor tun2socks bridge that
// pumps the platform tun device through it.
type XRayTunnel struct {
	inst      *core.Instance
	bridge    *tun2socks
	closeOnce sync.Once
}

// UpXRay configures and brings up an XRay/REALITY tunnel over tunDev. Like Up
// (AmneziaWG), the caller owns the tun device (creation, addressing, routing) —
// a utun on macOS, the OS-provided fd on mobile, wintun on Windows. The engine
// starts an in-process xray-core client bound to a loopback SOCKS port and
// bridges every tun flow to it via a userspace netstack.
func UpXRay(cfg XRayConfig, tunDev tun.Device) (*XRayTunnel, error) {
	socksPort, err := reserveLoopbackPort()
	if err != nil {
		return nil, fmt.Errorf("vp: reserve socks port: %w", err)
	}
	cfgJSON, err := cfg.clientJSON(socksPort)
	if err != nil {
		return nil, err
	}
	inst, err := startXray(cfgJSON)
	if err != nil {
		return nil, err
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultTunMTU
	}
	bridge, err := newTun2Socks(tunDev, mtu, fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		_ = inst.Close()
		return nil, err
	}
	bridge.start()
	return &XRayTunnel{inst: inst, bridge: bridge}, nil
}

// Close tears the tunnel down: stops the netstack bridge, then the xray client.
// The caller still owns (and closes) the tun device.
func (t *XRayTunnel) Close() error {
	t.closeOnce.Do(func() {
		if t.bridge != nil {
			t.bridge.stop()
		}
		if t.inst != nil {
			_ = t.inst.Close()
		}
	})
	return nil
}

// Stats returns cumulative received/transmitted bytes through the tunnel,
// counted at the tun2socks splice. ok is false before the bridge is up.
func (t *XRayTunnel) Stats() (rx, tx int64, ok bool) {
	if t.bridge == nil {
		return 0, 0, false
	}
	rx, tx = t.bridge.counts()
	return rx, tx, true
}

// startXray loads a JSON config and starts an embedded xray-core instance.
func startXray(cfgJSON string) (*core.Instance, error) {
	cfg, err := serial.LoadJSONConfig(bytes.NewReader([]byte(cfgJSON)))
	if err != nil {
		return nil, fmt.Errorf("vp: load xray config: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("vp: new xray instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return nil, fmt.Errorf("vp: start xray: %w", err)
	}
	return inst, nil
}

// clientJSON renders the xray-core client config: a loopback SOCKS inbound (the
// tun2socks target) and a single VLESS+REALITY outbound to the node.
func (cfg XRayConfig) clientJSON(socksPort int) (string, error) {
	host, portStr, err := net.SplitHostPort(cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("vp: xray endpoint %q: %w", cfg.Endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("vp: xray endpoint port %q: %w", portStr, err)
	}
	fp := cfg.Fingerprint
	if fp == "" {
		fp = defaultXRayFingerprint
	}

	c := xrayClientConfig{
		Log: xrayLog{LogLevel: "warning"},
		Inbounds: []xrayInbound{{
			Listen:   "127.0.0.1",
			Port:     socksPort,
			Protocol: "socks",
			Settings: xraySocksSettings{UDP: true},
		}},
		Outbounds: []xrayOutbound{{
			Protocol: "vless",
			Settings: xrayVLESSSettings{VNext: []xrayVNext{{
				Address: host,
				Port:    port,
				Users:   []xrayUser{{ID: cfg.UUID, Flow: cfg.Flow, Encryption: "none"}},
			}}},
			StreamSettings: xrayStream{
				Network:  "tcp",
				Security: "reality",
				Reality: xrayRealityClient{
					ServerName:  cfg.ServerName,
					Fingerprint: fp,
					PublicKey:   cfg.PublicKey,
					ShortID:     cfg.ShortID,
					SpiderX:     "/",
				},
			},
		}},
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("vp: encode xray config: %w", err)
	}
	return string(raw), nil
}

// reserveLoopbackPort returns a loopback TCP port free at the moment of the
// call — the xray SOCKS inbound binds it and the tun2socks bridge dials it.
func reserveLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// xray client config (the subset the engine emits).
type xrayClientConfig struct {
	Log       xrayLog        `json:"log"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
}
type xrayLog struct {
	LogLevel string `json:"loglevel"`
}
type xrayInbound struct {
	Listen   string            `json:"listen"`
	Port     int               `json:"port"`
	Protocol string            `json:"protocol"`
	Settings xraySocksSettings `json:"settings"`
}
type xraySocksSettings struct {
	UDP bool `json:"udp"`
}
type xrayOutbound struct {
	Protocol       string            `json:"protocol"`
	Settings       xrayVLESSSettings `json:"settings"`
	StreamSettings xrayStream        `json:"streamSettings"`
}
type xrayVLESSSettings struct {
	VNext []xrayVNext `json:"vnext"`
}
type xrayVNext struct {
	Address string     `json:"address"`
	Port    int        `json:"port"`
	Users   []xrayUser `json:"users"`
}
type xrayUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption"`
}
type xrayStream struct {
	Network  string            `json:"network"`
	Security string            `json:"security"`
	Reality  xrayRealityClient `json:"realitySettings"`
}
type xrayRealityClient struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}
