# tailnet-netd

A Lima usernet daemon that connects the guest to one tailnet and to nothing
else. Every TCP connection, UDP flow and DNS query of the guest goes through an
embedded Tailscale node ([tsnet](https://pkg.go.dev/tailscale.com/tsnet)), and
fails if the tailnet cannot carry it. The guest runs no Tailscale software and
never sees the node's key.

It takes the flags of `limactl usernet` and serves the same API, so Lima runs it
in place of its built-in daemon, by path, like `socket_vmnet`. No Tailscale code
enters Lima.

## Lima configuration

This needs the `daemon:` field of `networks.yaml` (see
`lima/website/content/en/docs/config/network/user-v2.md`). The `lima`
submodule pins the Lima branch that adds it.

`$LIMA_HOME/_config/networks.yaml`:

```yaml
networks:
  tailnet:
    mode: user-v2
    daemon: /usr/local/libexec/tailnet-netd   # absolute, owned by root
    gateway: 192.168.130.1
    netmask: 255.255.255.0
```

The instance:

```yaml
networks:
  - lima: tailnet
mounts:
  - location: "~/src"
    writable: true
```

Lima refuses to start an instance on such a network if it also has another
network, a reverse port forward, or a mount that contains `$LIMA_HOME` (such as
the default `~` mount). Each of those would give the guest a way around the
daemon: the node's key is in `$LIMA_HOME/_networks/<network>/tsnet`, and a
writable `$LIMA_HOME` would let the guest rewrite `networks.yaml`.

Lima stops with an error if the daemon is not owned by root, or exits before it
is ready, for example because it cannot join the tailnet within two minutes.

## Node configuration

Lima passes no options for the node, so they come from the environment of
`limactl`:

| Variable | Meaning | Default |
|---|---|---|
| `TS_AUTHKEY` | auth key to enrol the node | none: the node must already be enrolled |
| `TS_CONTROL_URL` | coordination server | Tailscale's |
| `TS_HOSTNAME` | device name | `lima-workspace` |
| `TS_EXIT_NODE` | `none`, `auto`, or a stable node ID | `none`: tailnet destinations only |
| `TS_EPHEMERAL` | remove the node when it goes offline | `false` |

Logs are not uploaded to Tailscale.

`--policy` is refused: filter traffic with the tailnet's access controls.

## What the guest sees

- DHCP gives it an address in the subnet, with the gateway (the network
  address plus two, `192.168.130.2` above) as router and DNS server, and the
  MagicDNS suffix as search domain.
- DNS names Lima registers (`host.lima.internal`, `lima-<instance>.internal`,
  `hostResolver.hosts`) are answered by the daemon. Unlike Lima's built-in
  daemon, other names in those zones are not NXDOMAIN, so a tailnet whose
  MagicDNS suffix ends in `.internal` still resolves. Every other query goes to
  the node's resolver, which answers MagicDNS names and forwards the rest to the tailnet's nameservers
  through the tailnet. A query it cannot resolve that way fails.
- TCP and UDP to global unicast IPv4 addresses outside the subnet go through
  the tailnet. Everything else (the gateway's other ports, loopback,
  link-local, multicast and broadcast addresses) is refused.

The node's identity is available on the API socket:

```console
$ curl --unix-socket "$LIMA_HOME/_networks/tailnet/tailnet_ep.sock" http://lima/extension/tailnet
{"ip":"100.64.0.7","hostname":"ws-alice","magicDNSSuffix":"example.internal","dnsName":"ws-alice.example.internal"}
```

## How containment is enforced

tsnet sends a dial that no peer routes through the host's network, and its DNS
forwarder dials upstream nameservers the same way. The daemon forces every dial
of the node into the tailnet (`tsdial.Dialer.UseNetstackForIP`) before the node
connects, and refuses to start if it cannot. Without this, the guest reaches the
host's network and the internet, and DNS queries leak to resolvers outside the
tailnet; the tests below fail in that case.

gvisor-tap-vsock's DNS server is not used because it resolves names with the
host's resolver.

## Limitations

- IPv4 only, like Lima's built-in daemon.
- ICMP is not carried, so `ping` does not show what is reachable.

## Testing

```sh
go test ./...                    # unit tests and a guest without a tailnet
HEADSCALE_TEST=1 go test ./...   # a guest on a headscale tailnet (needs Docker)
```

The tests attach a guest, a gVisor network stack exchanging Ethernet frames
over the daemon's QEMU socket, and check what it can reach, as a VM would see
it. With headscale, they check that the guest:

- reaches a peer over TCP and UDP, and resolves MagicDNS names;
- does not reach a TCP or UDP service on the host's network address, the host's
  loopback, or `1.1.1.1:443`, although the host itself does;
- gets no answer when the tailnet's nameserver is the host's own address, which
  answers the host.

Removing the netstack pin makes the host network, internet and DNS tests fail.

`LIMA_E2E=1` adds tests that drive a `limactl` built from the `lima` submodule
(`git submodule update --init`). They
check that Lima refuses the instances described above and a daemon not owned by
root. With a root-owned daemon, they also check that Lima fails when the daemon
exits, and boot a VM on a headscale tailnet to check its network from inside:

```sh
go build -o /tmp/tailnet-netd ./cmd/tailnet-netd
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec
sudo install -o root -g wheel -m 0755 /tmp/tailnet-netd /usr/local/libexec/tailnet-netd
LIMA_E2E=1 HEADSCALE_TEST=1 LIMA_E2E_DAEMON=/usr/local/libexec/tailnet-netd go test ./internal/tailnet/
```
