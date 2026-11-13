// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/miekg/dns"
)

const dnsTimeout = 5 * time.Second

var validDNSChars = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// dnsServer answers the guest's queries on the gateway address. Names in zones
// added through the API, which Lima uses for host.lima.internal and
// hostResolver.hosts, are answered locally like gvproxy does. Every other query
// goes to the tailnet node's resolver, which answers MagicDNS names and forwards
// the rest to the tailnet's nameservers through the tailnet; if that fails, so
// does the query.
//
// gvproxy's DNS server is not used because it resolves other names with the
// host's resolver, which would leak them outside the tailnet.
type dnsServer struct {
	bridge *Bridge

	mu    sync.RWMutex
	zones []types.Zone
}

func (s *dnsServer) servers(udpConn net.PacketConn, tcpLn net.Listener) (udpSrv, tcpSrv *dns.Server) {
	udpSrv = &dns.Server{PacketConn: udpConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = max(size, int(opt.UDPSize()))
		}
		s.reply(w, req, "udp", size)
	})}
	tcpSrv = &dns.Server{Listener: tcpLn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		s.reply(w, req, "tcp", dns.MaxMsgSize)
	})}
	return udpSrv, tcpSrv
}

func (s *dnsServer) reply(w dns.ResponseWriter, req *dns.Msg, family string, size int) {
	resp := s.answer(req, family)
	resp.Truncate(size)
	_ = w.WriteMsg(resp)
}

func (s *dnsServer) answer(req *dns.Msg, family string) *dns.Msg {
	switch {
	case req.Opcode != dns.OpcodeQuery:
		return new(dns.Msg).SetRcode(req, dns.RcodeNotImplemented)
	case len(req.Question) != 1:
		return new(dns.Msg).SetRcode(req, dns.RcodeFormatError)
	}
	if resp, ok := s.answerLocal(req); ok {
		return resp
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	resp, err := s.forward(ctx, req, family)
	if err != nil {
		s.bridge.cfg.Logf("dns: %s %s: %v", dns.TypeToString[req.Question[0].Qtype], req.Question[0].Name, err)
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	}
	return resp
}

func (s *dnsServer) forward(ctx context.Context, req *dns.Msg, family string) (*dns.Msg, error) {
	query, err := req.Pack()
	if err != nil {
		return nil, err
	}
	out, err := s.bridge.QueryDNS(ctx, query, family)
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(out); err != nil {
		return nil, err
	}
	if resp.Id != req.Id {
		return nil, errors.New("response ID does not match the query")
	}
	return resp, nil
}

// answerLocal answers the query if a zone has a record for the name, or a
// default address. Unlike gvproxy's server, other names in a zone are not
// NXDOMAIN: Lima's zone for "<instance>.internal" would otherwise hide every
// name ending in ".internal", such as a tailnet's MagicDNS names.
func (s *dnsServer) answerLocal(req *dns.Msg) (*dns.Msg, bool) {
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, zone := range s.zones {
		suffix := "." + strings.ToLower(zone.Name)
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		host := strings.TrimSuffix(name, suffix)
		var ip net.IP
		for _, r := range zone.Records {
			if (r.Name != "" && strings.EqualFold(r.Name, host)) || (r.Regexp != nil && r.Regexp.MatchString(host)) {
				ip = r.IP
				break
			}
		}
		if ip == nil {
			ip = zone.DefaultIP
		}
		if ip == nil {
			continue
		}
		resp := new(dns.Msg).SetReply(req)
		resp.RecursionAvailable = true
		if q.Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   ip,
			})
		}
		return resp, true
	}
	return nil, false
}

func (s *dnsServer) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/all", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.zones)
	})
	mux.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var zone types.Zone
		if err := json.NewDecoder(r.Body).Decode(&zone); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := validateZone(zone); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.addZone(zone)
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func validateZone(zone types.Zone) error {
	switch {
	case zone.Name == "":
		return errors.New("zone name is required")
	case zone.Name == ".":
		return errors.New("cannot add root zone")
	case !dns.IsFqdn(zone.Name):
		return fmt.Errorf("zone name must be fully qualified (end with '.'): %s", zone.Name)
	case !validDNSChars.MatchString(zone.Name):
		return fmt.Errorf("zone name contains invalid characters: %s", zone.Name)
	case len(zone.Records) == 0 && (zone.DefaultIP == nil || zone.DefaultIP.IsUnspecified()):
		return errors.New("zone must have at least one record or a default IP")
	}
	if _, ok := dns.IsDomainName(zone.Name); !ok {
		return fmt.Errorf("invalid DNS zone name: %s", zone.Name)
	}
	for _, r := range zone.Records {
		switch {
		case r.Name == "":
			return errors.New("record name is required")
		case !validDNSChars.MatchString(r.Name):
			return fmt.Errorf("record name contains invalid characters: %s", r.Name)
		case r.IP == nil && r.Regexp == nil:
			return fmt.Errorf("record %s must have an IP or regexp", r.Name)
		}
	}
	return nil
}

// addZone adds zone, merging its records into an existing zone of the same name.
func (s *dnsServer) addZone(zone types.Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, z := range s.zones {
		if strings.EqualFold(z.Name, zone.Name) {
			zone.Name = z.Name
			zone.Records = append(zone.Records, z.Records...)
			s.zones[i] = zone
			return
		}
	}
	s.zones = append(s.zones, zone)
}
