// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID      = 1
	gatewayMAC = "5a:94:ef:e4:0c:dd" // the address `limactl usernet` uses
)

// Options are the settings Lima passes to a usernet daemon.
type Options struct {
	// Subnet is the guest network, given by its network address, e.g.
	// 192.168.130.0/24.
	Subnet netip.Prefix
	MTU    int
	// DefaultLeases maps guest IP addresses to MAC addresses.
	DefaultLeases map[string]string
	// Endpoint is the unix socket serving the HTTP API Lima uses.
	Endpoint string
	// QemuSocket accepts frames with QEMU's stream framing (qemu driver).
	QemuSocket string
	// FdSocket accepts a datagram socket over SCM_RIGHTS (vz and krunkit).
	FdSocket string
	Bridge   *Bridge
}

// Network is a gVisor stack attached to the guest's NIC that proxies every
// guest flow through a Bridge.
type Network struct {
	opts    Options
	gateway netip.Addr
	stack   *stack.Stack
	sw      *tap.Switch
	ipPool  *tap.IPPool
	fwd     *forwarder.PortsForwarder
	dns     *dnsServer
}

// GatewayIP returns the address Lima configures in the guest as its gateway and
// DNS server: the subnet's network address plus two.
func GatewayIP(subnet netip.Prefix) (netip.Addr, error) {
	if !subnet.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("subnet %s is not IPv4", subnet)
	}
	if subnet != subnet.Masked() {
		return netip.Addr{}, fmt.Errorf("subnet %s is not a network address (want %s)", subnet, subnet.Masked())
	}
	if bits := subnet.Bits(); bits < 8 || bits > 30 {
		return netip.Addr{}, fmt.Errorf("subnet %s must have a prefix between /8 and /30", subnet)
	}
	return subnet.Addr().Next().Next(), nil
}

// New assembles the network without serving it.
func New(opts Options) (*Network, error) {
	if opts.Bridge == nil {
		return nil, errors.New("tailnet: Options.Bridge is nil")
	}
	gateway, err := GatewayIP(opts.Subnet)
	if err != nil {
		return nil, err
	}
	if opts.MTU == 0 {
		opts.MTU = 1500
	}

	ipPool, err := tap.NewIPPool(opts.Subnet.String())
	if err != nil {
		return nil, err
	}
	if err := ipPool.Reserve(gateway.String(), gatewayMAC); err != nil {
		return nil, err
	}
	for ip, mac := range opts.DefaultLeases {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !opts.Subnet.Contains(addr) || addr == gateway {
			continue
		}
		if err := ipPool.Reserve(ip, mac); err != nil {
			return nil, fmt.Errorf("reserving lease %s: %w", ip, err)
		}
	}

	linkEP, err := tap.NewLinkEndpoint(false, uint32(opts.MTU), gatewayMAC, gateway.String(), []string{gateway.String()})
	if err != nil {
		return nil, err
	}
	sw := tap.NewSwitch(false)
	linkEP.Connect(sw)
	sw.Connect(linkEP)

	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := st.CreateNIC(nicID, linkEP); err != nil {
		return nil, errors.New(err.String())
	}
	if err := st.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(gateway.As4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}
	// Promiscuous mode and spoofing let the stack terminate guest flows to any
	// destination, so that each one can be proxied.
	st.SetSpoofing(nicID, true)
	st.SetPromiscuousMode(nicID, true)
	guestSubnet, err := tcpip.NewSubnet(tcpip.AddrFrom4(opts.Subnet.Addr().As4()), tcpip.MaskFromBytes(net.CIDRMask(opts.Subnet.Bits(), 32)))
	if err != nil {
		return nil, err
	}
	st.SetRouteTable([]tcpip.Route{{Destination: guestSubnet, NIC: nicID}})

	n := &Network{
		opts:    opts,
		gateway: gateway,
		stack:   st,
		sw:      sw,
		ipPool:  ipPool,
		fwd:     forwarder.NewPortsForwarder(st),
		dns:     &dnsServer{bridge: opts.Bridge},
	}
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, n.tcpForwarder())
	st.SetTransportProtocolHandler(udp.ProtocolNumber, n.udpForwarder())
	return n, nil
}

// Serve runs the network until ctx is done or a service fails.
//
// The FdSocket is created last: Lima treats its existence as the daemon being
// ready, and connects the VM to it.
func (n *Network) Serve(ctx context.Context) error {
	dhcpSrv, err := dhcp.New(n.dhcpConfig(), n.stack, n.ipPool)
	if err != nil {
		return fmt.Errorf("dhcp: %w", err)
	}
	defer dhcpSrv.Underlying.Close()

	dnsUDP, dnsTCP, err := n.listenDNS()
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	udpSrv, tcpSrv := n.dns.servers(dnsUDP, dnsTCP)

	api := &http.Server{Handler: n.mux(dhcpSrv), ReadTimeout: 10 * time.Second}
	var listeners []net.Listener
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	listen := func(path string) (net.Listener, error) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, ln)
		return ln, nil
	}
	apiLn, err := listen(n.opts.Endpoint)
	if err != nil {
		return err
	}
	var qemuLn, fdLn net.Listener
	if n.opts.QemuSocket != "" {
		if qemuLn, err = listen(n.opts.QemuSocket); err != nil {
			return err
		}
	}
	if n.opts.FdSocket != "" {
		if fdLn, err = listen(n.opts.FdSocket); err != nil {
			return err
		}
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		<-ctx.Done()
		_ = api.Close()
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
		_ = dhcpSrv.Underlying.Close()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		return nil
	})
	serve := func(name string, f func() error) {
		g.Go(func() error {
			if err := f(); err != nil && ctx.Err() == nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		})
	}
	serve("dhcp", dhcpSrv.Serve)
	serve("dns/udp", udpSrv.ActivateAndServe)
	serve("dns/tcp", tcpSrv.ActivateAndServe)
	serve("api", func() error { return api.Serve(apiLn) })
	if qemuLn != nil {
		serve("qemu", func() error { return n.acceptQemu(ctx, qemuLn) })
	}
	if fdLn != nil {
		serve("fd", func() error { return n.acceptBess(ctx, fdLn) })
	}
	return g.Wait()
}

func (n *Network) listenDNS() (*gonet.UDPConn, *gonet.TCPListener, error) {
	addr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(n.gateway.As4()), Port: 53}
	udpConn, err := gonet.DialUDP(n.stack, &addr, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, nil, err
	}
	tcpLn, err := gonet.ListenTCP(n.stack, addr, ipv4.ProtocolNumber)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	return udpConn, tcpLn, nil
}

// dhcpConfig advertises the gateway as router and DNS server, and the MagicDNS
// suffix as search domain so that bare peer names resolve.
func (n *Network) dhcpConfig() *types.Configuration {
	var search []string
	if s := n.opts.Bridge.MagicDNSSuffix(); s != "" {
		search = append(search, s)
	}
	return &types.Configuration{
		MTU:               n.opts.MTU,
		Subnet:            n.opts.Subnet.String(),
		GatewayIP:         n.gateway.String(),
		GatewayMacAddress: gatewayMAC,
		GatewayVirtualIPs: []string{n.gateway.String()},
		DNSSearchDomains:  search,
	}
}

func (n *Network) mux(dhcpSrv *dhcp.Server) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/services/dhcp/", http.StripPrefix("/services/dhcp", dhcpSrv.Mux()))
	mux.Handle("/services/dns/", http.StripPrefix("/services/dns", n.dns.mux()))
	mux.Handle("/services/forwarder/", http.StripPrefix("/services/forwarder", n.fwd.Mux()))
	mux.HandleFunc("/extension/wait_port", n.handleWaitPort)
	mux.HandleFunc("/extension/tailnet", n.handleTailnet)
	return mux
}

// handleTailnet reports the node's tailnet identity, so that it does not have
// to be configured anywhere else.
func (n *Network) handleTailnet(w http.ResponseWriter, _ *http.Request) {
	b := n.opts.Bridge
	info := struct {
		IP             string `json:"ip"`
		Hostname       string `json:"hostname"`
		MagicDNSSuffix string `json:"magicDNSSuffix,omitempty"`
		DNSName        string `json:"dnsName,omitempty"`
	}{
		IP:             b.NodeIP().String(),
		Hostname:       b.Hostname(),
		MagicDNSSuffix: b.MagicDNSSuffix(),
		DNSName:        b.DNSName(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// handleWaitPort waits until the guest accepts TCP connections on a port; Lima
// calls it before connecting to the guest's SSH server.
func (n *Network) handleWaitPort(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip, err := netip.ParseAddr(q.Get("ip"))
	if err != nil || !n.opts.Subnet.Contains(ip) {
		http.Error(w, "ip must be a guest address", http.StatusBadRequest)
		return
	}
	port, err := strconv.ParseUint(q.Get("port"), 10, 16)
	if err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	timeout := 10 * time.Second
	if s := q.Get("timeout"); s != "" {
		secs, err := strconv.Atoi(s)
		if err != nil || secs < 0 {
			http.Error(w, "invalid timeout", http.StatusBadRequest)
			return
		}
		timeout = time.Duration(secs) * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	addr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(ip.As4()), Port: uint16(port)}
	for {
		if conn, err := gonet.DialContextTCP(ctx, n.stack, addr, ipv4.ProtocolNumber); err == nil {
			_ = conn.Close()
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case <-ctx.Done():
			http.Error(w, "timed out waiting for the port", http.StatusRequestTimeout)
			return
		case <-time.After(time.Second):
		}
	}
}
