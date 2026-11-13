// SPDX-License-Identifier: BSD-2-Clause

package tailnet

// These tests drive a limactl built from the lima submodule, so that the contract
// between Lima and the daemon (the arguments, the readiness signal, the
// validation of instances) is tested against Lima itself.
//
//	LIMA_E2E=1              enables them
//	LIMA_E2E_BIN=...        uses this limactl instead of building one
//	LIMA_E2E_DAEMON=...     the daemon to run, which Lima requires to be
//	                        owned by root:
//
//	go build -o /tmp/tailnet-netd ./cmd/tailnet-netd
//	sudo install -d -o root -g wheel -m 0755 /usr/local/libexec
//	sudo install -o root -g wheel -m 0755 /tmp/tailnet-netd /usr/local/libexec/tailnet-netd
//	LIMA_E2E=1 LIMA_E2E_DAEMON=/usr/local/libexec/tailnet-netd HEADSCALE_TEST=1 go test ./internal/tailnet/
//
// Booting a VM additionally needs HEADSCALE_TEST=1, since the daemon serves
// the guest only once it has joined a tailnet.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const limaInstance = `vmType: vz
cpus: 1
memory: 1GiB
disk: 5GiB
images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: aarch64
ssh:
  loadDotSSHPubKeys: false
networks:
  - lima: tailnet
%s`

type limaEnv struct {
	bin  string
	home string   // LIMA_HOME
	env  []string // in addition to os.Environ
}

// newLimaEnv returns a LIMA_HOME whose "tailnet" network is served by daemon.
// With fakeHome, HOME is a new directory containing LIMA_HOME, as it is by
// default; otherwise LIMA_HOME is outside HOME so that Lima's image cache is
// shared with the user's.
func newLimaEnv(t *testing.T, daemon string, fakeHome bool) *limaEnv {
	t.Helper()
	if os.Getenv("LIMA_E2E") != "1" {
		t.Skip("set LIMA_E2E=1 to run the tests that drive limactl")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("the instance uses vz on arm64")
	}
	e := &limaEnv{bin: buildLimactl(t)}
	// Lima's socket paths must stay under 104 bytes.
	if fakeHome {
		home := shortTempDir(t, "h")
		e.home = filepath.Join(home, ".lima")
		e.env = append(e.env, "HOME="+home)
	} else {
		e.home = shortTempDir(t, "lh")
	}
	e.env = append(e.env, "LIMA_HOME="+e.home)
	varRun := shortTempDir(t, "vr")
	config := fmt.Sprintf(`paths:
  varRun: %s
networks:
  tailnet:
    mode: user-v2
    daemon: %s
    gateway: 192.168.130.1
    netmask: 255.255.255.0
`, varRun, daemon)
	if err := os.MkdirAll(filepath.Join(e.home, "_config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.home, "_config", "networks.yaml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *limaEnv) run(t *testing.T, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.bin, args...)
	cmd.Env = append(os.Environ(), e.env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// start runs `limactl start` for an instance with the given extra YAML.
func (e *limaEnv) start(t *testing.T, timeout time.Duration, extra string) (string, error) {
	t.Helper()
	spec := filepath.Join(shortTempDir(t, "spec"), "ws.yaml")
	if err := os.WriteFile(spec, []byte(fmt.Sprintf(limaInstance, extra)), 0o644); err != nil {
		t.Fatal(err)
	}
	return e.run(t, timeout, "start", "--name=ws", "--tty=false", spec)
}

// shell runs script in the guest and returns its standard output.
func (e *limaEnv) shell(t *testing.T, script string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.bin, "shell", "ws", "--", "bash", "-c", script)
	cmd.Env = append(os.Environ(), e.env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(out), err
}

// TestLimaRefusesBypass checks that Lima refuses instances that would let the
// guest reach the host or the daemon's state other than through the daemon.
// The instances are not plain, since plain mode drops mounts and forwards.
func TestLimaRefusesBypass(t *testing.T) {
	daemon := buildDaemon(t)
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"home mount", "mounts:\n  - location: \"~\"\n", "exposes LIMA_HOME"},
		{"second network", "  - vzNAT: true\n", "must be the only network"},
		{"reverse forward", "portForwards:\n  - guestSocket: /run/x.sock\n    hostSocket: /tmp/x.sock\n    reverse: true\n", "must be false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLimaEnv(t, daemon, true)
			out, err := e.start(t, time.Minute, tc.yaml)
			if err == nil {
				_, _ = e.run(t, 2*time.Minute, "delete", "--force", "ws")
				t.Fatalf("limactl start succeeded:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("limactl start failed without %q:\n%s", tc.want, out)
			}
		})
	}
}

// TestLimaRefusesUnownedDaemon checks that Lima does not run a daemon that a
// user could have replaced.
func TestLimaRefusesUnownedDaemon(t *testing.T) {
	daemon := filepath.Join(t.TempDir(), "tailnet-netd")
	if err := copyFile(buildDaemon(t), daemon); err != nil {
		t.Fatal(err)
	}
	if isRootOwned(t, daemon) {
		t.Skip("running as root")
	}
	e := newLimaEnv(t, daemon, false)
	out, err := e.start(t, time.Minute, "plain: true\n")
	if err == nil {
		t.Fatalf("limactl start succeeded with a daemon not owned by root:\n%s", out)
	}
	if !strings.Contains(out, "is not owned by") {
		t.Errorf("limactl start failed without an ownership error:\n%s", out)
	}
}

// TestLimaFailsWhenDaemonExits checks that `limactl start` fails, rather than
// waiting forever, when the daemon cannot start.
func TestLimaFailsWhenDaemonExits(t *testing.T) {
	daemon := rootOwnedDaemon(t)
	e := newLimaEnv(t, daemon, false)
	e.env = append(e.env, "TS_EPHEMERAL=invalid")
	out, err := e.start(t, 10*time.Minute, "plain: true\n")
	if err == nil {
		t.Fatalf("limactl start succeeded:\n%s", out)
	}
	if !strings.Contains(out, "exited before it was ready") {
		t.Errorf("limactl start failed without naming the daemon exit:\n%s", out)
	}
}

// TestLimaBootsOnTailnet boots a VM and checks, from inside the guest, that it
// is configured by the daemon, reaches the tailnet, and reaches nothing else.
func TestLimaBootsOnTailnet(t *testing.T) {
	daemon := rootOwnedDaemon(t)
	e := newLimaEnv(t, daemon, false)
	hs := startHeadscale(t)
	key := hs.PreauthKey(t)
	peer := startBridge(t, hs, key, "e2e-peer")
	ln, err := peer.ts.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln, "peer")
	hostLn, err := net.Listen("tcp", netip.AddrPortFrom(hostIP(t), 0).String())
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, hostLn, "host")
	requireHostTCP(t, netip.MustParseAddrPort(hostLn.Addr().String()))

	e.env = append(e.env, "TS_CONTROL_URL="+hs.URL, "TS_AUTHKEY="+key, "TS_HOSTNAME=e2e-vm", "TS_DEBUG_USE_DERP_HTTP=true")
	t.Cleanup(func() {
		if t.Failed() {
			log, _ := os.ReadFile(filepath.Join(e.home, "_networks", "tailnet", "usernet.tailnet.stderr.log"))
			t.Logf("daemon log:\n%s", log)
		}
	})
	if out, err := e.start(t, 10*time.Minute, "plain: true\n"); err != nil {
		t.Fatalf("limactl start: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = e.run(t, 2*time.Minute, "delete", "--force", "ws") })

	info := daemonInfo(t, filepath.Join(e.home, "_networks", "tailnet", "tailnet_ep.sock"))
	if !strings.HasPrefix(info.IP, "100.") || info.DNSName != "e2e-vm.example.internal" {
		t.Errorf("daemon identity = %+v", info)
	}

	for _, c := range []struct{ name, script, want string }{
		{"one interface", `ip -o -4 addr show scope global | wc -l`, "1"},
		{"address", `ip -o -4 addr show scope global | awk '{print $4}'`, "192.168.130."},
		{"default route", `ip -4 route show default | awk '{print $3}'`, "192.168.130.2"},
		{"nameserver", `resolvectl dns | grep -o '192\.168\.130\.[0-9]*' | sort -u`, "192.168.130.2"},
		{"magicdns", `getent ahostsv4 e2e-peer.example.internal | awk 'NR==1{print $1}'`, peer.NodeIP().String()},
		{"host.lima.internal", `getent ahostsv4 host.lima.internal | awk 'NR==1{print $1}'`, "192.168.130.2"},
		{"peer", fmt.Sprintf(`timeout 10 cat </dev/tcp/%s/8080`, peer.NodeIP()), "peer"},
	} {
		out, err := e.shell(t, c.script)
		if err != nil || !strings.HasPrefix(strings.TrimSpace(out), c.want) {
			t.Errorf("%s: got %q (%v), want %q", c.name, strings.TrimSpace(out), err, c.want)
		}
	}
	for _, c := range []struct{ name, script string }{
		{"host network", fmt.Sprintf(`timeout 5 cat </dev/tcp/%s`, strings.Replace(hostLn.Addr().String(), ":", "/", 1))},
		{"internet", `timeout 5 bash -c '</dev/tcp/1.1.1.1/443'`},
		{"public name", `getent ahostsv4 example.com`},
	} {
		if out, err := e.shell(t, c.script); err == nil {
			t.Errorf("%s: reachable from the guest:\n%s", c.name, out)
		}
	}
}

type tailnetInfo struct {
	IP      string `json:"ip"`
	DNSName string `json:"dnsName"`
}

func daemonInfo(t *testing.T, endpoint string) tailnetInfo {
	t.Helper()
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", endpoint)
		},
	}}
	resp, err := c.Get("http://lima/extension/tailnet")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var info tailnetInfo
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("/extension/tailnet: %v: %s", err, body)
	}
	return info
}

var (
	limactlOnce sync.Once
	limactlBin  string
	limactlErr  error
	daemonOnce  sync.Once
	daemonBin   string
	daemonErr   error
)

// buildLimactl builds limactl from the lima submodule, signed so that it may use
// Virtualization.framework.
func buildLimactl(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("LIMA_E2E_BIN"); p != "" {
		return p
	}
	limactlOnce.Do(func() {
		src := filepath.Join(moduleRoot(t), "lima")
		dir, err := os.MkdirTemp("", "limactl")
		if err != nil {
			limactlErr = err
			return
		}
		bin := filepath.Join(dir, "limactl")
		for _, args := range [][]string{
			{"go", "build", "-o", bin, "./cmd/limactl"},
			{"codesign", "-f", "--entitlements", "vz.entitlements", "-s", "-", bin},
		} {
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Dir = src
			if out, err := cmd.CombinedOutput(); err != nil {
				limactlErr = fmt.Errorf("%v: %w\n%s", args, err, out)
				return
			}
		}
		limactlBin = bin
	})
	if limactlErr != nil {
		t.Fatal(limactlErr)
	}
	return limactlBin
}

func buildDaemon(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("LIMA_E2E_DAEMON"); p != "" {
		return p
	}
	daemonOnce.Do(func() {
		dir, err := os.MkdirTemp("", "netd")
		if err != nil {
			daemonErr = err
			return
		}
		bin := filepath.Join(dir, "tailnet-netd")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/tailnet-netd")
		cmd.Dir = moduleRoot(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			daemonErr = fmt.Errorf("building the daemon: %w\n%s", err, out)
			return
		}
		daemonBin = bin
	})
	if daemonErr != nil {
		t.Fatal(daemonErr)
	}
	return daemonBin
}

func rootOwnedDaemon(t *testing.T) string {
	t.Helper()
	daemon := buildDaemon(t)
	if !isRootOwned(t, daemon) {
		t.Skipf("%s is not owned by root, so Lima will not run it; set LIMA_E2E_DAEMON (see the top of this file)", daemon)
	}
	return daemon
}

func isRootOwned(t *testing.T, path string) bool {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
