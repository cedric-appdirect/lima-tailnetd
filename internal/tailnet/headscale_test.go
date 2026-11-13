// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

// This file runs a real headscale control server in a container so the daemon
// can be tested against an actual tailnet instead of a mock.
//
// Why this matters: the daemon's whole claim is "the guest's traffic leaves
// through this tailnet node and nothing else". That claim is not testable by
// asserting on function calls -- it needs a control plane that hands out an
// address, a WireGuard tunnel, and a peer to reach. headscale provides all three
// locally, with no Tailscale account and no traffic leaving the machine.
//
// Skipped unless HEADSCALE_TEST=1, because it needs a Docker daemon and takes
// tens of seconds; CI should set the variable, a plain `go test` should not.

const (
	headscaleImage = "headscale/headscale:v0.29.7"
	// headscalePort must match `server_url` in headscaleConfig: it is both the
	// API endpoint and the DERP relay address handed to nodes.
	headscalePort = "8080"
)

// headscaleConfig is the minimal config that boots v0.29.7, with the tailnet's
// global nameservers left to fill in. Note the embedded
// DERP server: headscale refuses to start with an empty DERPMap, even for
// loopback-only tests.
const headscaleConfig = `
server_url: http://127.0.0.1:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: true
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls: []
  paths:
    - /etc/headscale/derp.yaml
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
dns:
  magic_dns: true
  base_domain: example.internal
  nameservers:
    global: [%s]
  override_local_dns: %t
unix_socket: /var/run/headscale/headscale.sock
log:
  level: info
  format: text
policy:
  mode: database
`

// headscaleInstance is a running control server plus the handles needed to
// create users and preauth keys.
//
// DERP map note: `paths` in the config is the right mechanism, and
// `insecurefortests: true` is the right spelling (verified against v0.29.7's
// loader, which uses plain yaml.Unmarshal so the lower-case Go field name
// matches; `InsecureForTests` and `insecure_for_tests` both fail to decode).
//
// The map is delivered with the *netmap*, not with Status(): reading
// `LocalClient().CurrentDERPMap` immediately after Start returns an empty map and
// makes it look like the config was ignored. Poll it.
type headscaleInstance struct {
	ctr testcontainers.Container
	URL string // e.g. http://127.0.0.1:8080
	// DERP is the relay this control server hands to its nodes. Tests that need
	// traffic to actually flow depend on it.
	DERP *testDERP
}

// startHeadscale boots headscale, with nameservers as the tailnet's global
// nameservers, and returns it. The test is skipped unless HEADSCALE_TEST=1.
func startHeadscale(t *testing.T, nameservers ...string) *headscaleInstance {
	t.Helper()

	if os.Getenv("HEADSCALE_TEST") != "1" {
		t.Skip("set HEADSCALE_TEST=1 and run a Docker daemon to exercise the real control plane")
	}

	// Start our own DERP relay first: headscale's embedded one serves plain HTTP
	// while advertising itself as non-insecure, which makes every relay path fail.
	// The relay's port is dynamic, so its map must exist before headscale starts.
	derp := startDERP(t)

	dir := t.TempDir()
	derpPath := filepath.Join(dir, "derp.yaml")
	if err := os.WriteFile(derpPath, []byte(derp.Map), 0o644); err != nil {
		t.Fatalf("write derp map: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	config := fmt.Sprintf(headscaleConfig, strings.Join(nameservers, ", "), len(nameservers) > 0)
	if err := os.WriteFile(cfgPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        headscaleImage,
		ExposedPorts: []string{"8080/tcp", "3478/udp"},
		// headscale advertises its DERP relay using server_url, which is baked
		// into config.yaml and cannot know a random mapped port. Bind 8080 to
		// 8080 on the host so the URL the nodes are handed actually resolves.
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.PortBindings = network.PortMap{
				network.MustParsePort("8080/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: headscalePort}},
				network.MustParsePort("3478/udp"): {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "3478"}},
			}
		},
		Cmd: []string{"serve"},
		// headscale only describes the relay to the nodes, which dial it on the
		// host directly.
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfgPath, ContainerFilePath: "/etc/headscale/config.yaml", FileMode: 0o644},
			{HostFilePath: derpPath, ContainerFilePath: "/etc/headscale/derp.yaml", FileMode: 0o644},
		},
		WaitingFor: wait.ForHTTP("/health").WithPort("8080/tcp").WithStartupTimeout(90 * time.Second),
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("could not start headscale container: %v", err)
	}
	t.Cleanup(func() {
		_ = ctr.Terminate(context.Background())
	})

	url := fmt.Sprintf("http://127.0.0.1:%s", headscalePort)
	return &headscaleInstance{ctr: ctr, URL: url, DERP: derp}
}

// exec runs a headscale CLI command inside the container.
func (h *headscaleInstance) exec(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code, reader, err := h.ctr.Exec(ctx, append([]string{"headscale"}, args...), exec.Multiplexed())
	if err != nil {
		t.Fatalf("exec headscale %v: %v", args, err)
	}
	out, _ := io.ReadAll(reader)
	if code != 0 {
		t.Fatalf("headscale %v exited %d: %s", args, code, out)
	}
	return string(out)
}

// PreauthKey creates a user (idempotently) and returns a reusable preauth key.
//
// headscale v0.29's `--user` flag takes a numeric user ID, not a name, so the
// ID is looked up after creating the user rather than assumed.
func (h *headscaleInstance) PreauthKey(t *testing.T) string {
	t.Helper()
	// "User created" or a duplicate error -- either is fine.
	_, _, _ = h.ctr.Exec(context.Background(), []string{"headscale", "users", "create", "wstest"}, exec.Multiplexed())

	out := h.exec(t, "users", "list", "--output", "json")
	userID := userIDFromList(t, out, "wstest")

	out = h.exec(t, "preauthkeys", "create", "--user", userID,
		"--reusable", "--expiration", "1h")
	key := strings.TrimSpace(out)
	// The CLI may print a warning line before the key; take the line that looks
	// like one.
	for _, line := range strings.Split(key, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "hskey-") {
			return line
		}
	}
	t.Fatalf("could not parse a preauth key from output: %q", out)
	return ""
}

// userIDFromList extracts the numeric ID for name from `users list --output json`.
func userIDFromList(t *testing.T, out, name string) string {
	t.Helper()
	var users []struct {
		ID   any    `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &users); err != nil {
		t.Fatalf("parse users list: %v (output: %q)", err, out)
	}
	for _, u := range users {
		if u.Name == name {
			switch v := u.ID.(type) {
			case float64:
				return strconv.FormatInt(int64(v), 10)
			case string:
				return v
			}
		}
	}
	t.Fatalf("user %q not found in %q", name, out)
	return ""
}
