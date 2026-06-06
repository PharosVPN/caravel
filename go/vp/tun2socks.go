// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package vp

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/net/proxy"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tunOffset is the read/write offset wireguard-go-style tun devices reserve in
// front of each packet (virtio header room). The IP packet starts at this
// offset in every buffer.
const tunOffset = 16

const t2sNICID = tcpip.NICID(1)

// tun2socks bridges a platform tun device to a SOCKS5 proxy via a userspace
// gVisor network stack: it terminates the apps' TCP/UDP flows in the netstack
// and re-originates each as a connection to the local xray-core SOCKS inbound,
// which carries it out over VLESS+REALITY. Cross-platform: it uses gVisor's
// channel endpoint (pure Go) over the tun.Device abstraction, not the Linux-only
// fdbased endpoint.
type tun2socks struct {
	dev    tun.Device
	mtu    int
	dialer proxy.Dialer

	stack *stack.Stack
	ep    *channel.Endpoint

	ctx    context.Context
	cancel context.CancelFunc

	rx, tx atomic.Int64
}

func newTun2Socks(dev tun.Device, mtu int, socksAddr string) (*tun2socks, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("vp: socks dialer: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &tun2socks{dev: dev, mtu: mtu, dialer: d, ctx: ctx, cancel: cancel}
	if err := t.buildStack(); err != nil {
		cancel()
		return nil, err
	}
	return t, nil
}

func (t *tun2socks) buildStack() error {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, uint32(t.mtu), "")
	if err := s.CreateNIC(t2sNICID, ep); err != nil {
		return fmt.Errorf("vp: create NIC: %s", err)
	}
	// Transparent gateway: accept packets for any destination and originate
	// replies from arbitrary addresses.
	s.SetPromiscuousMode(t2sNICID, true)
	s.SetSpoofing(t2sNICID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: t2sNICID},
		{Destination: header.IPv6EmptySubnet, NIC: t2sNICID},
	})

	// Each TCP SYN to any destination becomes a SOCKS connection to that
	// original destination (the xray client then carries it over REALITY).
	fwd := tcp.NewForwarder(s, 0, 2048, t.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	t.stack = s
	t.ep = ep
	return nil
}

// start launches the two pump goroutines: tun -> netstack and netstack -> tun.
func (t *tun2socks) start() {
	go t.inbound()
	go t.outbound()
}

// stop cancels the bridge and closes the netstack. The caller owns the tun
// device; closing it unblocks the inbound read loop.
func (t *tun2socks) stop() {
	t.cancel()
	if t.ep != nil {
		t.ep.Close()
	}
	if t.stack != nil {
		t.stack.Close()
	}
}

func (t *tun2socks) counts() (rx, tx int64) { return t.rx.Load(), t.tx.Load() }

// inbound reads IP packets off the tun and injects them into the netstack.
func (t *tun2socks) inbound() {
	batch := t.dev.BatchSize()
	if batch <= 0 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, tunOffset+t.mtu+virtioHeadroom)
	}
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}
		n, err := t.dev.Read(bufs, sizes, tunOffset)
		if err != nil {
			return // tun closed by its owner
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][tunOffset : tunOffset+sizes[i]]
			var proto tcpip.NetworkProtocolNumber
			switch header.IPVersion(pkt) {
			case header.IPv4Version:
				proto = header.IPv4ProtocolNumber
			case header.IPv6Version:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			t.ep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}
}

// virtioHeadroom is extra slack so a tun read with GSO/virtio framing always
// fits in the buffer.
const virtioHeadroom = 80

// outbound drains packets the netstack produces and writes them to the tun.
func (t *tun2socks) outbound() {
	for {
		pkt := t.ep.ReadContext(t.ctx)
		if pkt == nil {
			return // ctx cancelled
		}
		data := pkt.ToView().AsSlice()
		buf := make([]byte, tunOffset+len(data))
		copy(buf[tunOffset:], data)
		_, _ = t.dev.Write([][]byte{buf}, tunOffset)
		pkt.DecRef()
	}
}

// handleTCP dials the SOCKS proxy for the flow's original destination and
// splices the netstack endpoint to it.
func (t *tun2socks) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := net.JoinHostPort(addrString(id.LocalAddress), strconv.Itoa(int(id.LocalPort)))

	remote, err := t.dialer.Dial("tcp", dst)
	if err != nil {
		r.Complete(true) // send RST
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		remote.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	go t.splice(local, remote)
}

// splice copies bytes both ways and accounts them: app->net is tx, net->app is
// rx (from the device's perspective).
func (t *tun2socks) splice(local, remote net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(remote, local) // app -> internet
		t.tx.Add(n)
		closeWrite(remote)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(local, remote) // internet -> app
		t.rx.Add(n)
		closeWrite(local)
		done <- struct{}{}
	}()
	<-done
	<-done
	local.Close()
	remote.Close()
}

// closeWrite half-closes the write side if supported, so the peer sees EOF
// while the other direction keeps draining.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func addrString(a tcpip.Address) string { return net.IP(a.AsSlice()).String() }
