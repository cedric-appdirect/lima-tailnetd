// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"

	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/types/key"
)

// testDERP is a DERP relay for the tailnet tests, which need one whenever the
// nodes find no direct UDP path to each other.
type testDERP struct {
	URL      string // e.g. http://127.0.0.1:53421
	RegionID int
	// Map is the DERP map to hand to the control server, so nodes are told to
	// use this relay.
	Map string
}

// startDERP runs a DERP relay on a loopback port.
//
// The relay speaks plain HTTP, which nodes use only with
// TS_DEBUG_USE_DERP_HTTP; InsecureForTests merely skips certificate checks.
// Nodes started by the test process get the knob here; a daemon started by
// Lima needs it in its environment.
func startDERP(t *testing.T) *testDERP {
	t.Helper()
	envknob.Setenv("TS_DEBUG_USE_DERP_HTTP", "true")

	key := key.NewNode()
	srv := derpserver.New(key, func(format string, args ...any) {
		t.Logf("[derp] "+format, args...)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("derp listen: %v", err)
	}

	// derphttp clients connect to the server root, not to /derp.
	httpSrv := &http.Server{
		Handler:      derpserver.Handler(srv),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	port := ln.Addr().(*net.TCPAddr).Port
	const regionID = 900
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	// The YAML form headscale's `derp.paths` accepts.
	derpMap := fmt.Sprintf(`regions:
  %d:
    regionid: %d
    regioncode: local
    regionname: local
    nodes:
      - name: %da
        regionid: %d
        hostname: 127.0.0.1
        derpport: %d
        insecurefortests: true
`, regionID, regionID, regionID, regionID, port)

	return &testDERP{URL: url, RegionID: regionID, Map: derpMap}
}
