// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	gvclient "github.com/containers/gvisor-tap-vsock/pkg/client"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// These helpers run the daemon's network as Lima would, and attach a guest to
// it: a separate gVisor stack exchanging Ethernet frames with the daemon over
// its QEMU socket. Everything a test asserts is therefore observed from the
// guest's side of the virtual NIC, as a VM would observe it.

var (
	testSubnet  = netip.MustParsePrefix("192.168.130.0/24")
	testGateway = netip.MustParseAddr("192.168.130.2")
	testGuestIP = netip.MustParseAddr("192.168.130.15")
)

const testGuestMAC = "52:55:55:12:34:56"

type testNetwork struct {
	*Network
	http *http.Client
	api  *gvclient.Client
}

// get returns the status of a GET request to the daemon's API.
func (n *testNetwork) get(t *testing.T, path string) int {
	t.Helper()
	resp, err := n.http.Get("http://lima" + path)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// startNetwork serves a Network for bridge until the test ends.
func startNetwork(t *testing.T, bridge *Bridge) *testNetwork {
	t.Helper()
	dir := shortTempDir(t, "netd")
	n, err := New(Options{
		Subnet:        testSubnet,
		DefaultLeases: map[string]string{testGuestIP.String(): testGuestMAC},
		Endpoint:      filepath.Join(dir, "ep.sock"),
		QemuSocket:    filepath.Join(dir, "qemu.sock"),
		Bridge:        bridge,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	waitForSocket(t, n.opts.QemuSocket)

	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", n.opts.Endpoint)
		},
	}}
	tn := &testNetwork{Network: n, http: httpClient, api: gvclient.New(httpClient, "http://lima")}
	// The zones Lima's AddDNSHosts adds for an instance named "ws".
	for _, zone := range []types.Zone{
		{Name: "lima.internal.", Records: []types.Record{{Name: "host", IP: net.IP(testGateway.AsSlice())}}},
		{Name: "internal.", Records: []types.Record{{Name: "lima-ws", IP: net.IP(testGuestIP.AsSlice())}}},
	} {
		if err := tn.api.AddDNS(&zone); err != nil {
			t.Fatalf("AddDNS: %v", err)
		}
	}
	return tn
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for range 100 {
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s never appeared", path)
}

// testGuest is a guest attached to a testNetwork.
type testGuest struct {
	stack *stack.Stack
}

// attachGuest connects a guest with address testGuestIP and a default route
// through gateway.
func attachGuest(t *testing.T, n *testNetwork, gateway netip.Addr) *testGuest {
	t.Helper()
	conn, err := net.Dial("unix", n.opts.QemuSocket)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := net.ParseMAC(testGuestMAC)
	if err != nil {
		t.Fatal(err)
	}
	ch := channel.New(256, 1500, tcpip.LinkAddress(mac))
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := st.CreateNIC(1, ethernet.New(ch)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(testGuestIP.As4()),
			PrefixLen: testSubnet.Bits(),
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4(gateway.As4()), NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = conn.Close()
		st.Close()
	})
	// QEMU's stream framing: a 4-byte big-endian length, then the frame.
	go func() {
		for {
			pkt := ch.ReadContext(ctx)
			if pkt == nil {
				return
			}
			frame := pkt.ToView().AsSlice()
			msg := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(frame)), uint32(len(frame)))
			pkt.DecRef()
			if _, err := conn.Write(append(msg, frame...)); err != nil {
				return
			}
		}
	}()
	go func() {
		var size [4]byte
		for {
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return
			}
			frame := make([]byte, binary.BigEndian.Uint32(size[:]))
			if _, err := io.ReadFull(conn, frame); err != nil {
				return
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
			ch.InjectInbound(0, pkt)
			pkt.DecRef()
		}
	}()
	return &testGuest{stack: st}
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ap.Addr().As4()), Port: ap.Port()}
}

func (g *testGuest) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, g.stack, fullAddr(dst), ipv4.ProtocolNumber)
}

func (g *testGuest) dialUDP(dst netip.AddrPort) (*gonet.UDPConn, error) {
	return gonet.DialUDP(g.stack, nil, ptrTo(fullAddr(dst)), ipv4.ProtocolNumber)
}

func (g *testGuest) listenTCP(port uint16) (net.Listener, error) {
	return gonet.ListenTCP(g.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(testGuestIP.As4()), Port: port}, ipv4.ProtocolNumber)
}

// query sends a DNS query to the gateway over network ("udp" or "tcp").
func (g *testGuest) query(t *testing.T, network, name string, qtype uint16) (*dns.Msg, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*dnsTimeout)
	defer cancel()
	server := netip.AddrPortFrom(testGateway, 53)
	var conn net.Conn
	var err error
	if network == "tcp" {
		conn, err = g.dialTCP(ctx, server)
	} else {
		conn, err = g.dialUDP(server)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * dnsTimeout))
	dc := &dns.Conn{Conn: conn}
	if err := dc.WriteMsg(new(dns.Msg).SetQuestion(dns.Fqdn(name), qtype)); err != nil {
		return nil, err
	}
	return dc.ReadMsg()
}

// tcpReachable reports whether the guest can open a TCP connection to dst and
// read want from it.
func (g *testGuest) tcpReachable(dst netip.AddrPort, want string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := g.dialTCP(ctx, dst)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != want {
		return errors.New("unexpected banner " + string(buf))
	}
	return nil
}

// udpEchoes reports whether a datagram the guest sends to dst comes back.
func (g *testGuest) udpEchoes(dst netip.AddrPort) error {
	conn, err := g.dialUDP(dst)
	if err != nil {
		return err
	}
	defer conn.Close()
	return udpEcho(conn)
}

func udpEcho(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != "ping" {
		return errors.New("unexpected reply " + string(buf[:n]))
	}
	return nil
}

func ptrTo[T any](v T) *T { return &v }

// serveBanner accepts connections on ln and writes banner to each.
func serveBanner(t *testing.T, ln net.Listener, banner string) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(banner))
			_ = c.Close()
		}
	}()
}

// serveUDPEcho echoes every datagram received on pc.
func serveUDPEcho(t *testing.T, pc net.PacketConn) {
	t.Helper()
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
}
