// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// These tests attach a guest to the daemon's network, with the daemon joined to
// a headscale tailnet, and check what the guest can and cannot reach. Every
// "cannot" case first checks that the host itself can reach the destination,
// so that a failure from the guest shows that the daemon refused to carry the
// traffic rather than that nothing was there.

func startBridge(t *testing.T, hs *headscaleInstance, key, name string) *Bridge {
	t.Helper()
	b := NewBridge(BridgeConfig{
		Dir:        t.TempDir(),
		Hostname:   name,
		AuthKey:    key,
		ControlURL: hs.URL,
		Logf:       func(string, ...any) {},
	})
	t.Cleanup(func() { _ = b.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("%s: Start: %v", name, err)
	}
	return b
}

func eventually(t *testing.T, timeout time.Duration, f func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %s: %v", timeout, err)
		}
		time.Sleep(time.Second)
	}
}

// hostIP returns an IPv4 address of the host other than loopback, or skips.
func hostIP(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && p.Addr().IsGlobalUnicast() {
			return p.Addr()
		}
	}
	t.Skip("the host has no non-loopback IPv4 address to test against")
	return netip.Addr{}
}

// tailnetGuest returns a guest of a daemon joined to hs, and a peer on the
// same tailnet that serves a TCP banner and a UDP echo, once the guest can
// reach the peer.
func tailnetGuest(t *testing.T, hs *headscaleInstance) (*testGuest, *Bridge) {
	t.Helper()
	key := hs.PreauthKey(t)
	peer := startBridge(t, hs, key, "e2e-peer")
	ws := startBridge(t, hs, key, "e2e-ws")

	ln, err := peer.ts.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln, "peer")
	pc, err := peer.ts.ListenPacket("udp", netip.AddrPortFrom(peer.NodeIP(), 9000).String())
	if err != nil {
		t.Fatal(err)
	}
	serveUDPEcho(t, pc)

	g := attachGuest(t, startNetwork(t, ws), testGateway)
	eventually(t, 60*time.Second, func() error {
		return g.tcpReachable(netip.AddrPortFrom(peer.NodeIP(), 8080), "peer")
	})
	return g, peer
}

func TestGuestTailnet(t *testing.T) {
	hs := startHeadscale(t)
	g, peer := tailnetGuest(t, hs)

	t.Run("udp to peer", func(t *testing.T) {
		if err := g.udpEchoes(netip.AddrPortFrom(peer.NodeIP(), 9000)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("magicdns", func(t *testing.T) {
		for _, network := range []string{"udp", "tcp"} {
			for _, name := range []string{"e2e-peer.example.internal", "e2e-ws.example.internal"} {
				resp, err := g.query(t, network, name, dns.TypeA)
				if err != nil {
					t.Fatalf("%s %s: %v", network, name, err)
				}
				if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
					t.Fatalf("%s %s: %v", network, name, resp)
				}
			}
		}
		resp, _ := g.query(t, "udp", "e2e-peer.example.internal", dns.TypeA)
		if got := resp.Answer[0].(*dns.A).A.String(); got != peer.NodeIP().String() {
			t.Errorf("e2e-peer resolved to %s, want %s", got, peer.NodeIP())
		}
	})

	t.Run("host tcp", func(t *testing.T) {
		ln, err := net.Listen("tcp", netip.AddrPortFrom(hostIP(t), 0).String())
		if err != nil {
			t.Fatal(err)
		}
		serveBanner(t, ln, "host")
		dst := netip.MustParseAddrPort(ln.Addr().String())
		requireHostTCP(t, dst)
		if err := g.tcpReachable(dst, "host"); err == nil {
			t.Fatalf("the guest reached %s on the host's network", dst)
		}
	})

	t.Run("host udp", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", netip.AddrPortFrom(hostIP(t), 0).String())
		if err != nil {
			t.Fatal(err)
		}
		serveUDPEcho(t, pc)
		dst := netip.MustParseAddrPort(pc.LocalAddr().String())
		conn, err := net.Dial("udp", dst.String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := udpEcho(conn); err != nil {
			t.Fatalf("control: the host cannot reach %s: %v", dst, err)
		}
		if err := g.udpEchoes(dst); err == nil {
			t.Fatalf("the guest reached %s on the host's network", dst)
		}
	})

	t.Run("host loopback", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serveBanner(t, ln, "host")
		port := netip.MustParseAddrPort(ln.Addr().String()).Port()
		requireHostTCP(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
		for _, ip := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), testGateway} {
			if err := g.tcpReachable(netip.AddrPortFrom(ip, port), "host"); err == nil {
				t.Errorf("the guest reached the host's loopback through %s", ip)
			}
		}
	})

	t.Run("internet", func(t *testing.T) {
		dst := netip.MustParseAddrPort("1.1.1.1:443")
		conn, err := net.DialTimeout("tcp", dst.String(), 5*time.Second)
		if err != nil {
			t.Skipf("control: the host cannot reach %s: %v", dst, err)
		}
		_ = conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if conn, err := g.dialTCP(ctx, dst); err == nil {
			_ = conn.Close()
			t.Fatalf("the guest reached %s without an exit node", dst)
		}
	})
}

func requireHostTCP(t *testing.T, dst netip.AddrPort) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", dst.String(), 5*time.Second)
	if err != nil {
		t.Fatalf("control: the host cannot reach %s: %v", dst, err)
	}
	_ = conn.Close()
}

// TestGuestDNSDoesNotLeak points the tailnet's nameserver at the host's own
// address. The tailnet node may only reach it through the tailnet, which has no
// route to it, so the guest's queries must fail even though the host gets
// answers from it.
func TestGuestDNSDoesNotLeak(t *testing.T) {
	ip := hostIP(t)
	server := netip.AddrPortFrom(ip, 53).String()
	// Answer on the host's address unless something already does. macOS lets
	// unprivileged processes bind port 53 only on the wildcard address.
	if pc, err := net.ListenPacket("udp4", ":53"); err == nil {
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg).SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(203, 0, 113, 1),
			})
			_ = w.WriteMsg(resp)
		})}
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	if _, _, err := new(dns.Client).Exchange(new(dns.Msg).SetQuestion("example.com.", dns.TypeA), server); err != nil {
		t.Skipf("control: the host gets no answer from %s: %v", server, err)
	}

	hs := startHeadscale(t, strconv.Quote(ip.String()))
	g, _ := tailnetGuest(t, hs)

	// MagicDNS still works, so the forwarding path to the tailnet resolver is
	// up and the failures below are the tailnet resolver failing.
	if resp, err := g.query(t, "udp", "e2e-peer.example.internal", dns.TypeA); err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("e2e-peer.example.internal = %v, %v", resp, err)
	}
	for _, network := range []string{"udp", "tcp"} {
		resp, err := g.query(t, network, "example.com", dns.TypeA)
		var netErr net.Error
		switch {
		case errors.As(err, &netErr) && netErr.Timeout():
		case err != nil:
			t.Fatalf("%s: %v", network, err)
		case resp.Rcode != dns.RcodeServerFailure:
			t.Errorf("%s: the guest got an answer from a nameserver outside the tailnet:\n%v", network, resp)
		}
	}
}
