// SPDX-License-Identifier: BSD-2-Clause

// tailnet-netd is a Lima usernet daemon that connects the guest to a tailnet
// and to nothing else: every connection and every DNS query of the guest goes
// through an embedded Tailscale node, and fails if the tailnet cannot carry it.
//
// It takes the flags of `limactl usernet` and serves the same API. Lima runs it
// in place of the built-in daemon for networks that set `daemon:` in
// networks.yaml:
//
//	networks:
//	  tailnet:
//	    mode: user-v2
//	    daemon: /usr/local/libexec/tailnet-netd
//	    gateway: 192.168.130.1
//	    netmask: 255.255.255.0
//
// The node is configured from the environment, since Lima passes no options for
// it: TS_AUTHKEY, TS_CONTROL_URL, TS_HOSTNAME (default "lima-workspace"),
// TS_EXIT_NODE ("none" by default, "auto", or a stable node ID) and
// TS_EPHEMERAL. The node's state is kept in a "tsnet" directory next to the
// pidfile.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cedric-appdirect/lima-tailnetd/internal/tailnet"
)

// startTimeout bounds how long the node may take to join the tailnet; Lima
// waits for the daemon until then.
const startTimeout = 2 * time.Minute

func main() {
	cfg, err := parseArgs(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tailnet-netd: %v\n", err)
		os.Exit(2)
	}
	log.SetPrefix("tailnet-netd: ")
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	pidFile    string
	endpoint   string
	listenQemu string
	listenFD   string
	subnet     netip.Prefix
	mtu        int
	leases     map[string]string
	bridge     tailnet.BridgeConfig
}

func parseArgs(args []string, output io.Writer) (config, error) {
	var (
		cfg            config
		subnet, leases string
		policy         string
	)
	fs := flag.NewFlagSet("tailnet-netd", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&cfg.pidFile, "pidfile", "", "write PID to file")
	fs.StringVar(&cfg.pidFile, "p", "", "shorthand for -pidfile")
	fs.StringVar(&cfg.endpoint, "endpoint", "", "serve the usernet API on this unix socket")
	fs.StringVar(&cfg.endpoint, "e", "", "shorthand for -endpoint")
	fs.StringVar(&cfg.listenQemu, "listen-qemu", "", "listen for QEMU connections on this unix socket")
	fs.StringVar(&cfg.listenFD, "listen", "", "listen for SCM_RIGHTS socket handoffs on this unix socket")
	fs.StringVar(&subnet, "subnet", "192.168.5.0/24", "guest network, by its network address")
	fs.IntVar(&cfg.mtu, "mtu", 1500, "MTU")
	fs.StringVar(&leases, "leases", "", "static DHCP leases: ip=mac,...")
	fs.StringVar(&policy, "policy", "", "not supported")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	// The tailnet's ACLs are the policy; ignoring a policy file would leave
	// traffic unfiltered that its author meant to filter.
	if policy != "" {
		return cfg, errors.New("-policy is not supported: filter traffic with the tailnet's access controls")
	}
	if cfg.endpoint == "" {
		return cfg, errors.New("-endpoint is required")
	}
	if cfg.pidFile == "" {
		return cfg, errors.New("-pidfile is required: the node state is kept next to it")
	}

	var err error
	if cfg.subnet, err = netip.ParsePrefix(subnet); err != nil {
		return cfg, fmt.Errorf("-subnet: %w", err)
	}
	if _, err := tailnet.GatewayIP(cfg.subnet); err != nil {
		return cfg, fmt.Errorf("-subnet: %w", err)
	}
	if cfg.leases, err = parseLeases(leases); err != nil {
		return cfg, fmt.Errorf("-leases: %w", err)
	}

	ephemeral := false
	if s := os.Getenv("TS_EPHEMERAL"); s != "" {
		if ephemeral, err = strconv.ParseBool(s); err != nil {
			return cfg, fmt.Errorf("TS_EPHEMERAL: %w", err)
		}
	}
	cfg.bridge = tailnet.BridgeConfig{
		Dir:        filepath.Join(filepath.Dir(cfg.pidFile), "tsnet"),
		Hostname:   envOr("TS_HOSTNAME", "lima-workspace"),
		AuthKey:    os.Getenv("TS_AUTHKEY"),
		ControlURL: os.Getenv("TS_CONTROL_URL"),
		ExitNode:   envOr("TS_EXIT_NODE", "none"),
		Ephemeral:  ephemeral,
		Logf:       log.Printf,
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseLeases parses the "ip=mac,ip=mac" form of `limactl usernet --leases`.
func parseLeases(s string) (map[string]string, error) {
	leases := make(map[string]string)
	if s == "" {
		return leases, nil
	}
	for pair := range strings.SplitSeq(s, ",") {
		ip, mac, ok := strings.Cut(pair, "=")
		if !ok || ip == "" || mac == "" {
			return nil, fmt.Errorf("invalid lease %q", pair)
		}
		leases[ip] = mac
	}
	return leases, nil
}

func run(cfg config) error {
	pf, err := os.OpenFile(cfg.pidFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(pf, "%d\n", os.Getpid())
	if cerr := pf.Close(); err == nil {
		err = cerr
	}
	defer os.Remove(cfg.pidFile)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(cfg.bridge.Dir, 0o700); err != nil {
		return err
	}
	bridge := tailnet.NewBridge(cfg.bridge)
	defer bridge.Close()
	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	err = bridge.Start(startCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("joining the tailnet: %w", err)
	}

	nw, err := tailnet.New(tailnet.Options{
		Subnet:        cfg.subnet,
		MTU:           cfg.mtu,
		DefaultLeases: cfg.leases,
		Endpoint:      cfg.endpoint,
		QemuSocket:    cfg.listenQemu,
		FdSocket:      cfg.listenFD,
		Bridge:        bridge,
	})
	if err != nil {
		return err
	}
	return nw.Serve(ctx)
}
