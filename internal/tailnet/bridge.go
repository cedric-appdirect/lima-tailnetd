// SPDX-License-Identifier: BSD-2-Clause

// Package tailnet implements a Lima usernet daemon whose every guest connection
// leaves through one embedded Tailscale node (tsnet), with no fallback to the
// host's network.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// BridgeConfig configures the embedded tailnet node.
type BridgeConfig struct {
	// Dir holds the node's state, including its private key.
	Dir string
	// Hostname is the tailnet device name.
	Hostname string
	// AuthKey enrols the node; empty means Dir must already hold an enrolled node.
	AuthKey string
	// ControlURL is the coordination server; empty means Tailscale's.
	ControlURL string
	// ExitNode carries traffic for destinations outside the tailnet: "" or
	// "none" (such destinations are unreachable), "auto", or a stable node ID.
	ExitNode string
	// Ephemeral removes the node from the tailnet when it goes offline.
	Ephemeral bool
	// Logf receives the node's logs; nil means log.Printf.
	Logf func(format string, args ...any)
}

// Bridge owns the tsnet node, which is the daemon's only way to the network.
type Bridge struct {
	cfg BridgeConfig
	ts  *tsnet.Server

	started        bool
	nodeIP         netip.Addr
	magicDNSSuffix string
}

// NewBridge returns a Bridge that is not started yet.
func NewBridge(cfg BridgeConfig) *Bridge {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Bridge{
		cfg: cfg,
		ts: &tsnet.Server{
			Dir:        cfg.Dir,
			Hostname:   cfg.Hostname,
			AuthKey:    cfg.AuthKey,
			ControlURL: cfg.ControlURL,
			Ephemeral:  cfg.Ephemeral,
			Logf:       cfg.Logf,
			UserLogf:   cfg.Logf,
		},
	}
}

// Start brings the node up and returns once it is connected to the tailnet, or
// when ctx is done.
func (b *Bridge) Start(ctx context.Context) error {
	// tsnet uploads its logs to Tailscale unless this is set, whatever the
	// control server.
	envknob.SetNoLogsNoSupport()

	if err := b.ts.Start(); err != nil {
		return fmt.Errorf("tsnet: %w", err)
	}

	// tsnet dials destinations it does not route to a peer through the host's
	// network stack, and its DNS forwarder uses the same dialer for upstream
	// resolvers. Forcing every dial into the netstack leaves those destinations
	// unreachable instead. This must happen before the node has a netmap, which
	// is what makes any such dial possible.
	dialer, ok := b.ts.Sys().Dialer.GetOK()
	if !ok {
		return errors.New("tsnet dialer unavailable: cannot disable its host-network fallback")
	}
	dialer.UseNetstackForIP = func(netip.Addr) bool { return true }

	lc, err := b.ts.LocalClient()
	if err != nil {
		return err
	}
	if err := setExitNode(ctx, lc, b.cfg.ExitNode); err != nil {
		return err
	}

	watcher, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		return err
	}
	defer watcher.Close()
	for {
		n, err := watcher.Next()
		if err != nil {
			return fmt.Errorf("waiting for the tailnet: %w", err)
		}
		if n.ErrMessage != nil {
			return fmt.Errorf("tailnet: %s", *n.ErrMessage)
		}
		if n.BrowseToURL != nil && *n.BrowseToURL != "" {
			b.cfg.Logf("tailnet login required: %s", *n.BrowseToURL)
		}
		if n.State != nil && *n.State == ipn.Running {
			break
		}
	}

	st, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	for _, ip := range st.TailscaleIPs {
		if ip.Is4() {
			b.nodeIP = ip
			break
		}
	}
	if st.CurrentTailnet != nil {
		b.magicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
	}
	b.started = true
	b.cfg.Logf("tailnet node up: ip=%s magicdns=%q exit-node=%q", b.nodeIP, b.magicDNSSuffix, b.cfg.ExitNode)
	return nil
}

func setExitNode(ctx context.Context, lc *local.Client, exitNode string) error {
	mp := &ipn.MaskedPrefs{AutoExitNodeSet: true, ExitNodeIDSet: true}
	switch exitNode {
	case "", "none":
	case "auto":
		mp.AutoExitNode = ipn.AnyExitNode
	default:
		mp.ExitNodeID = tailcfg.StableNodeID(exitNode)
	}
	if _, err := lc.EditPrefs(ctx, mp); err != nil {
		return fmt.Errorf("setting exit node %q: %w", exitNode, err)
	}
	return nil
}

// Dial connects to address through the tailnet.
func (b *Bridge) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !b.started {
		return nil, errors.New("tailnet node not started")
	}
	return b.ts.Dial(ctx, network, address)
}

// QueryDNS resolves a wire-format query with the node's resolver, the one that
// serves 100.100.100.100 to tailnet clients. family is "udp" or "tcp", the
// transport the query arrived on.
func (b *Bridge) QueryDNS(ctx context.Context, query []byte, family string) ([]byte, error) {
	if !b.started {
		return nil, errors.New("tailnet node not started")
	}
	mgr, ok := b.ts.Sys().DNSManager.GetOK()
	if !ok {
		return nil, errors.New("tailnet resolver unavailable")
	}
	return mgr.Query(ctx, query, family, netip.AddrPortFrom(b.nodeIP, 0))
}

// Close shuts the node down.
func (b *Bridge) Close() error { return b.ts.Close() }

// NodeIP returns the node's tailnet IPv4 address.
func (b *Bridge) NodeIP() netip.Addr { return b.nodeIP }

// Hostname returns the node's tailnet device name.
func (b *Bridge) Hostname() string { return b.cfg.Hostname }

// MagicDNSSuffix returns the tailnet's MagicDNS suffix, or "".
func (b *Bridge) MagicDNSSuffix() string { return b.magicDNSSuffix }

// DNSName returns the node's MagicDNS name, or "" without MagicDNS.
func (b *Bridge) DNSName() string {
	if b.magicDNSSuffix == "" {
		return ""
	}
	return b.cfg.Hostname + "." + b.magicDNSSuffix
}
