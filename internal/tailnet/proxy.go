// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	dialTimeout    = 10 * time.Second
	udpIdleTimeout = 30 * time.Second
)

// destination returns the address a guest flow is proxied to, and whether it
// may be proxied at all. Only global unicast IPv4 addresses outside the guest
// subnet are: the gateway serves DHCP and DNS itself, and loopback, link-local,
// broadcast and multicast addresses have no meaning on the tailnet.
func (n *Network) destination(id stack.TransportEndpointID) (string, bool) {
	ip, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok || !ip.Is4() || !ip.IsGlobalUnicast() || n.opts.Subnet.Contains(ip) || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return "", false
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(id.LocalPort))), true
}

func (n *Network) tcpForwarder() func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return tcp.NewForwarder(n.stack, 0, 1024, func(r *tcp.ForwarderRequest) {
		dest, ok := n.destination(r.ID())
		if !ok {
			r.Complete(true)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		remote, err := n.opts.Bridge.Dial(ctx, "tcp", dest)
		cancel()
		if err != nil {
			n.opts.Bridge.cfg.Logf("tcp %s: %v", dest, err)
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if tcpErr != nil {
			_ = remote.Close()
			return
		}
		proxy(gonet.NewTCPConn(&wq, ep), remote)
	}).HandlePacket
}

func (n *Network) udpForwarder() func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return udp.NewForwarder(n.stack, func(r *udp.ForwarderRequest) bool {
		dest, ok := n.destination(r.ID())
		if !ok {
			return true
		}
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			return true
		}
		guest := gonet.NewUDPConn(&wq, ep)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			remote, err := n.opts.Bridge.Dial(ctx, "udp", dest)
			cancel()
			if err != nil {
				n.opts.Bridge.cfg.Logf("udp %s: %v", dest, err)
				_ = guest.Close()
				return
			}
			proxyUDP(guest, remote)
		}()
		return true
	}).HandlePacket
}

type closeWriter interface {
	CloseWrite() error
}

// proxy copies between a and b in both directions until both are done.
func proxy(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// proxyUDP relays datagrams between guest and remote until either side has
// sent nothing for udpIdleTimeout.
func proxyUDP(guest *gonet.UDPConn, remote net.Conn) {
	defer guest.Close()
	defer remote.Close()
	relay := func(dst, src net.Conn) {
		buf := make([]byte, 64<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() {
		relay(guest, remote)
		close(done)
	}()
	relay(remote, guest)
	_ = remote.SetReadDeadline(time.Now())
	<-done
}
