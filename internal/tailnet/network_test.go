// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// shortTempDir returns a temporary directory whose path is short enough for
// unix sockets, which t.TempDir does not guarantee.
func shortTempDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func unstartedBridge(t *testing.T) *Bridge {
	return NewBridge(BridgeConfig{Dir: t.TempDir(), Hostname: "test", Logf: t.Logf})
}

func TestGatewayIP(t *testing.T) {
	for _, tc := range []struct {
		subnet string
		want   string // empty when the subnet must be refused
	}{
		// Lima passes the network address and configures the guest with .2.
		{"192.168.130.0/24", "192.168.130.2"},
		{"192.168.104.0/24", "192.168.104.2"},
		{"10.42.0.0/16", "10.42.0.2"},
		{"10.0.0.0/30", "10.0.0.2"},
		{"192.168.130.1/24", ""},
		{"192.168.130.2/24", ""},
		{"0.0.0.0/0", ""},
		{"10.0.0.0/4", ""},
		{"10.0.0.0/31", ""},
		{"fd00::/64", ""},
	} {
		t.Run(tc.subnet, func(t *testing.T) {
			got, err := GatewayIP(netip.MustParsePrefix(tc.subnet))
			if tc.want == "" {
				if err == nil {
					t.Fatalf("GatewayIP(%s) = %s, want an error", tc.subnet, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Errorf("GatewayIP(%s) = %s, want %s", tc.subnet, got, tc.want)
			}
		})
	}
}

func TestNewRefusesNilBridge(t *testing.T) {
	if _, err := New(Options{Subnet: testSubnet}); err == nil {
		t.Fatal("New accepted Options without a Bridge")
	}
}

func TestDestination(t *testing.T) {
	n, err := New(Options{Subnet: testSubnet, Bridge: unstartedBridge(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"100.64.0.7", true},
		{"1.1.1.1", true},
		{"10.1.2.3", true},
		{"192.168.130.2", false}, // the gateway
		{"192.168.130.15", false},
		{"192.168.130.255", false},
		{"127.0.0.1", false},
		{"169.254.169.254", false},
		{"224.0.0.251", false},
		{"255.255.255.255", false},
		{"0.0.0.0", false},
	} {
		id := stack.TransportEndpointID{LocalAddress: tcpip.AddrFrom4(netip.MustParseAddr(tc.addr).As4()), LocalPort: 443}
		dest, ok := n.destination(id)
		if ok != tc.ok {
			t.Errorf("destination(%s) = %q, %v; want ok=%v", tc.addr, dest, ok, tc.ok)
		}
	}
}

func TestDHCPAdvertisesGateway(t *testing.T) {
	n := startNetwork(t, unstartedBridge(t))
	g := attachGuest(t, n, testGateway)

	mac, _ := net.ParseMAC(testGuestMAC)
	discover, err := dhcpv4.NewDiscovery(mac)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := g.dialUDP(netip.AddrPortFrom(testGateway, 67))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(discover.ToBytes()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	nr, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no DHCP offer: %v", err)
	}
	offer, err := dhcpv4.FromBytes(buf[:nr])
	if err != nil {
		t.Fatal(err)
	}
	if got := offer.YourIPAddr.String(); got != testGuestIP.String() {
		t.Errorf("offered address %s, want the static lease %s", got, testGuestIP)
	}
	if got := offer.Router(); len(got) != 1 || got[0].String() != testGateway.String() {
		t.Errorf("router = %v, want %s", got, testGateway)
	}
	if got := offer.DNS(); len(got) != 1 || got[0].String() != testGateway.String() {
		t.Errorf("DNS = %v, want %s", got, testGateway)
	}
}

// TestDNSLocalZones checks the zones Lima adds for host.lima.internal and the
// instance's own name, which startNetwork adds through the client Lima uses.
func TestDNSLocalZones(t *testing.T) {
	n := startNetwork(t, unstartedBridge(t))
	for _, bad := range []types.Zone{
		{Name: ".", DefaultIP: net.ParseIP("10.0.0.1")},
		{Name: "not-fqdn", DefaultIP: net.ParseIP("10.0.0.1")},
		{Name: "empty.internal."},
		{Name: "bad.internal.", Records: []types.Record{{Name: "x"}}},
	} {
		if err := n.api.AddDNS(&bad); err == nil {
			t.Errorf("AddDNS(%+v) succeeded, want an error", bad)
		}
	}
	if zones, err := n.api.ListDNS(); err != nil || len(zones) != 2 {
		t.Fatalf("ListDNS = %+v, %v; want Lima's two zones", zones, err)
	}

	g := attachGuest(t, n, testGateway)
	for _, network := range []string{"udp", "tcp"} {
		for name, want := range map[string]netip.Addr{
			"HOST.lima.internal": testGateway,
			"lima-ws.internal":   testGuestIP,
		} {
			resp, err := g.query(t, network, name, dns.TypeA)
			if err != nil {
				t.Fatalf("%s %s: %v", network, name, err)
			}
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != want.String() {
				t.Errorf("%s %s A = %v, want %s", network, name, resp, want)
			}
		}
	}
	// The zones only serve A records: other types are NODATA, not forwarded.
	if resp, err := g.query(t, "udp", "host.lima.internal", dns.TypeAAAA); err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("host.lima.internal AAAA = %v, %v; want NODATA", resp, err)
	}
	// Other names in the zones, such as MagicDNS names under a tailnet's
	// ".internal" suffix, are forwarded to the tailnet, which is down here.
	for _, name := range []string{"other.lima.internal", "peer.example.internal"} {
		if resp, err := g.query(t, "udp", name, dns.TypeA); err != nil || resp.Rcode != dns.RcodeServerFailure {
			t.Errorf("%s A = %v, %v; want SERVFAIL from forwarding", name, resp, err)
		}
	}
}

// TestDNSFailsClosed checks that a name the daemon cannot resolve over the
// tailnet is an error for the guest, not something resolved some other way.
func TestDNSFailsClosed(t *testing.T) {
	n := startNetwork(t, unstartedBridge(t))
	g := attachGuest(t, n, testGateway)
	for _, network := range []string{"udp", "tcp"} {
		resp, err := g.query(t, network, "example.com", dns.TypeA)
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if resp.Rcode != dns.RcodeServerFailure || len(resp.Answer) != 0 {
			t.Errorf("%s: example.com A = %v, want SERVFAIL", network, resp)
		}
	}
}

func TestDNSRefusesMalformedQueries(t *testing.T) {
	s := &dnsServer{bridge: unstartedBridge(t)}
	two := new(dns.Msg).SetQuestion("a.example.", dns.TypeA)
	two.Question = append(two.Question, dns.Question{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if got := s.answer(two, "udp").Rcode; got != dns.RcodeFormatError {
		t.Errorf("two questions: rcode %s, want FORMERR", dns.RcodeToString[got])
	}
	notify := new(dns.Msg).SetNotify("example.")
	if got := s.answer(notify, "udp").Rcode; got != dns.RcodeNotImplemented {
		t.Errorf("NOTIFY: rcode %s, want NOTIMP", dns.RcodeToString[got])
	}
}

func TestDNSTruncatesUDP(t *testing.T) {
	s := &dnsServer{bridge: unstartedBridge(t)}
	records := make([]types.Record, 0, 64)
	for i := range 64 {
		records = append(records, types.Record{Name: "h" + strconv.Itoa(i), IP: net.IPv4(10, 0, 0, byte(i))})
	}
	s.addZone(types.Zone{Name: "big.internal.", Records: records})
	req := new(dns.Msg).SetQuestion("h1.big.internal.", dns.TypeA)
	resp := s.answer(req, "udp")
	resp.Truncate(dns.MinMsgSize)
	if resp.Len() > dns.MinMsgSize {
		t.Errorf("response of %d bytes exceeds %d", resp.Len(), dns.MinMsgSize)
	}
}

// TestSSHForward checks the path Lima uses to reach the guest's SSH server:
// wait_port, then a forward from a host port to the guest.
func TestSSHForward(t *testing.T) {
	n := startNetwork(t, unstartedBridge(t))
	g := attachGuest(t, n, testGateway)
	ln, err := g.listenTCP(22)
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln, "SSH-2.0-test\r\n")

	if code := n.get(t, "/extension/wait_port?ip="+testGuestIP.String()+"&port=22&timeout=5"); code != http.StatusOK {
		t.Fatalf("wait_port = %d, want 200", code)
	}
	if code := n.get(t, "/extension/wait_port?ip=127.0.0.1&port=22&timeout=1"); code != http.StatusBadRequest {
		t.Errorf("wait_port for a non-guest address = %d, want 400", code)
	}

	hostLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := hostLn.Addr().String()
	_ = hostLn.Close()
	if err := n.api.Expose(&types.ExposeRequest{Local: local, Remote: testGuestIP.String() + ":22", Protocol: "tcp"}); err != nil {
		t.Fatalf("Expose: %v", err)
	}
	conn, err := net.DialTimeout("tcp", local, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	banner, err := io.ReadAll(conn)
	if err != nil || string(banner) != "SSH-2.0-test\r\n" {
		t.Errorf("forwarded banner = %q, %v", banner, err)
	}
}

func TestStartFailsWithoutControlServer(t *testing.T) {
	b := NewBridge(BridgeConfig{
		Dir:        t.TempDir(),
		Hostname:   "test",
		AuthKey:    "not-a-key",
		ControlURL: "http://127.0.0.1:1",
		Logf:       func(string, ...any) {},
	})
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Start(ctx); err == nil {
		t.Fatal("Start succeeded without a control server")
	}
	if _, err := b.Dial(context.Background(), "tcp", "100.64.0.1:80"); err == nil {
		t.Error("Dial succeeded on a node that did not start")
	}
}
