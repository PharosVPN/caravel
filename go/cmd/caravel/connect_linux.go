// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/PharosVPN/caravel/core/profile"
	"github.com/PharosVPN/caravel/core/vp"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// ifaceName is the userspace AmneziaWG tun device caravel creates.
const ifaceName = "pharos0"

// cmdConnect brings up the AmneziaWG tunnel for a stored profile on a tun device,
// captures the default route (full tunnel) unless --no-default-route, and runs
// until interrupted (Ctrl-C / SIGTERM). Needs root for the tun device + routes.
func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	connRef := fs.String("connection", "", "named connection within the bundle (default: the first)")
	nodeID := fs.String("node", "", "node id within the connection (default: the entry/first)")
	noDefault := fs.Bool("no-default-route", false, "do not capture the default route (split tunnel)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	name := fs.Arg(0)
	if name == "" {
		return errors.New("usage: caravel connect <name> [--node ID] [--no-default-route]")
	}
	if err := initStore(); err != nil {
		return err
	}
	st, err := profile.NewStore(storeDir())
	if err != nil {
		return err
	}
	data, err := st.Raw(name)
	if err != nil {
		return err
	}
	p, err := profile.Parse(data, profile.Options{})
	if err != nil {
		return err
	}
	cp, err := p.Select(*connRef)
	if err != nil {
		return err
	}
	node, err := cp.Node(*nodeID)
	if err != nil {
		return err
	}
	t, err := node.Tunnel()
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root (tun + routes)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tn, err := connect(t, !*noDefault)
	if err != nil {
		return err
	}
	defer tn.Close()

	fmt.Printf("caravel: tunnel up on %s → %s (%s/%s, full-tunnel=%v). Ctrl-C to disconnect.\n",
		tn.iface, t.Endpoint, p.FleetID, t.NodeName, !*noDefault)
	<-ctx.Done()
	fmt.Println("\ncaravel: disconnecting")
	return nil
}

// tunnel is a running tunnel plus the host routes to undo on close.
type tunnel struct {
	vt    *vp.Tunnel
	iface string
	undo  []string // route destinations to `ip route del` on close (LIFO)
}

func connect(t *profile.Tunnel, full bool) (*tunnel, error) {
	mtu := t.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	dev, err := tun.CreateTUN(ifaceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("create %s (is the tun module loaded?): %w", ifaceName, err)
	}
	iface, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	vt, err := vp.Up(vp.Config{
		PrivateKey:      t.PrivateKey,
		ServerPublicKey: t.ServerPublicKey,
		PresharedKey:    t.PresharedKey,
		Endpoint:        t.Endpoint,
		AllowedIPs:      t.AllowedIPs,
		Keepalive:       t.Keepalive,
		Obfuscation:     toVPObfuscation(t.Obfuscation),
	}, dev, device.LogLevelError)
	if err != nil {
		dev.Close()
		return nil, err
	}
	tn := &tunnel{vt: vt, iface: iface}
	if err := tn.configureNetwork(t, mtu, full); err != nil {
		tn.Close()
		return nil, fmt.Errorf("configure network: %w", err)
	}
	return tn, nil
}

// configureNetwork addresses the tun device and, for a full tunnel, pins the
// server endpoint to its current real route and overrides the default with the
// 0.0.0.0/1 + 128.0.0.0/1 split — the same split-tunnel trick caravel-owrt uses
// (so reaching the endpoint is preserved while everything else flows through).
func (tn *tunnel) configureNetwork(t *profile.Tunnel, mtu int, full bool) error {
	if t.Address == "" {
		return errors.New("profile has no tunnel address")
	}
	if err := sh("ip", "addr", "add", t.Address+"/32", "dev", tn.iface); err != nil {
		return err
	}
	if err := sh("ip", "link", "set", "dev", tn.iface, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}

	captureDefault := full
	if !full {
		for _, cidr := range t.AllowedIPs {
			if isDefaultRoute(cidr) {
				captureDefault = true
				continue
			}
			if strings.Contains(cidr, ":") {
				continue // IPv4 only in this slice
			}
			if err := sh("ip", "route", "add", cidr, "dev", tn.iface); err != nil {
				return err
			}
			tn.undo = append(tn.undo, cidr)
		}
	}
	if !captureDefault {
		return nil
	}

	// Pin the endpoint to its current real route BEFORE stealing the default, so
	// the encrypted UDP to the node does not recurse into the tunnel.
	host, _, err := net.SplitHostPort(t.Endpoint)
	if err != nil {
		host = t.Endpoint
	}
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return fmt.Errorf("resolve endpoint %q: %w", host, err)
	}
	via, dev, err := routeTo(ip.String())
	if err != nil {
		return err
	}
	pin := []string{"ip", "route", "replace", ip.String() + "/32", "dev", dev}
	if via != "" {
		pin = []string{"ip", "route", "replace", ip.String() + "/32", "via", via, "dev", dev}
	}
	if err := sh(pin...); err != nil {
		return err
	}
	tn.undo = append(tn.undo, ip.String()+"/32")

	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := sh("ip", "route", "replace", half, "dev", tn.iface); err != nil {
			return err
		}
		tn.undo = append(tn.undo, half)
	}
	return nil
}

// Close tears down routes (reverse order) and the tunnel device.
func (tn *tunnel) Close() error {
	for i := len(tn.undo) - 1; i >= 0; i-- {
		_ = sh("ip", "route", "del", tn.undo[i])
	}
	tn.undo = nil
	if tn.vt != nil {
		tn.vt.Close()
		tn.vt = nil
	}
	return nil
}

// routeTo returns the gateway ("" if directly connected) and egress device the
// kernel would currently use to reach ip — read before we steal the default.
func routeTo(ip string) (via, dev string, err error) {
	out, err := exec.Command("ip", "route", "get", ip).Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route get %s: %w", ip, err)
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			via = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	if dev == "" {
		return "", "", fmt.Errorf("no egress device for %s", ip)
	}
	return via, dev, nil
}

// isDefaultRoute reports whether cidr is an IPv4/IPv6 default route.
func isDefaultRoute(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

// sh runs a command, surfacing stderr on failure.
func sh(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// toVPObfuscation maps a profile obfuscation set to the engine's.
func toVPObfuscation(o profile.Obfuscation) vp.Obfuscation {
	return vp.Obfuscation{
		Jc: o.Jc, Jmin: o.Jmin, Jmax: o.Jmax,
		S1: o.S1, S2: o.S2, S3: o.S3, S4: o.S4,
		H1: o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
		I1: o.I1, I2: o.I2, I3: o.I3, I4: o.I4, I5: o.I5,
	}
}
