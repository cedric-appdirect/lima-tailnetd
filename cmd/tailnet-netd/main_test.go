// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
)

// limaArgs is the argument vector Lima's usernet.Start passes to the daemon.
func limaArgs(extra ...string) []string {
	return append([]string{
		"-p", "/u/.lima/_networks/tailnet/usernet_tailnet.pid",
		"-e", "/u/.lima/_networks/tailnet/tailnet_ep.sock",
		"--listen-qemu", "/u/.lima/_networks/tailnet/tailnet_qemu.sock",
		"--listen", "/u/.lima/_networks/tailnet/tailnet_fd.sock",
		"--subnet", "192.168.130.0/24",
	}, extra...)
}

func TestParseArgsLima(t *testing.T) {
	t.Setenv("TS_HOSTNAME", "")
	t.Setenv("TS_EXIT_NODE", "")
	t.Setenv("TS_EPHEMERAL", "")
	cfg, err := parseArgs(limaArgs("--leases", "192.168.130.5=52:55:55:b3:bc:d9,192.168.130.6=5a:94:ef:e4:0c:df"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"pidfile", cfg.pidFile, "/u/.lima/_networks/tailnet/usernet_tailnet.pid"},
		{"endpoint", cfg.endpoint, "/u/.lima/_networks/tailnet/tailnet_ep.sock"},
		{"listen-qemu", cfg.listenQemu, "/u/.lima/_networks/tailnet/tailnet_qemu.sock"},
		{"listen", cfg.listenFD, "/u/.lima/_networks/tailnet/tailnet_fd.sock"},
		{"subnet", cfg.subnet.String(), "192.168.130.0/24"},
		{"state dir", cfg.bridge.Dir, "/u/.lima/_networks/tailnet/tsnet"},
		{"hostname", cfg.bridge.Hostname, "lima-workspace"},
		{"exit node", cfg.bridge.ExitNode, "none"},
		{"lease", cfg.leases["192.168.130.6"], "5a:94:ef:e4:0c:df"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if len(cfg.leases) != 2 {
		t.Errorf("leases = %v, want 2", cfg.leases)
	}
}

func TestParseArgsRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"policy", limaArgs("--policy", "/u/.lima/_networks/tailnet/policy.json"), "-policy is not supported"},
		{"no endpoint", []string{"-p", "/tmp/x.pid"}, "-endpoint is required"},
		{"no pidfile", []string{"-e", "/tmp/ep.sock"}, "-pidfile is required"},
		{"gateway as subnet", append(limaArgs(), "--subnet", "192.168.130.1/24"), "not a network address"},
		{"bad lease", limaArgs("--leases", "192.168.130.5"), "invalid lease"},
		{"positional", limaArgs("extra"), "unexpected arguments"},
		{"unknown flag", limaArgs("--tsnet-dir", "/tmp"), "not defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseArgs(tc.args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseArgs error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestParseArgsEnv(t *testing.T) {
	t.Setenv("TS_EPHEMERAL", "maybe")
	if _, err := parseArgs(limaArgs(), io.Discard); err == nil {
		t.Error("an invalid TS_EPHEMERAL was accepted")
	}
	t.Setenv("TS_EPHEMERAL", "true")
	t.Setenv("TS_EXIT_NODE", "auto")
	cfg, err := parseArgs(limaArgs(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.bridge.Ephemeral || cfg.bridge.ExitNode != "auto" {
		t.Errorf("bridge config = %+v", cfg.bridge)
	}
}

func TestParseArgsHelp(t *testing.T) {
	if _, err := parseArgs([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("parseArgs(-h) = %v, want flag.ErrHelp", err)
	}
}
