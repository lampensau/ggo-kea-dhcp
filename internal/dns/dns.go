// Package dns is the appliance's single owner of UDP port 53, with one explicit
// mode per lifecycle era: a captive redirector (every A query answered with the
// listener's own address, the FACTORY/ONBOARDING behavior) and the ACTIVE
// authoritative server for the device zones inv.greengo.digital and
// dhcp.greengo.digital plus a deliberately dumb forwarder to the uplink's
// resolver. One component, never two servers racing for the socket.
//
// Transport stance, decided and deliberate: UDP only. Answers are minimal
// single-record responses for a fleet of at most hundreds of names, so they
// always fit the classic 512-byte payload; anything that somehow would not gets
// the TC bit and no TCP listener to fall back to. No EDNS0 is negotiated for
// the server's own answers either. Forwarded queries and replies are relayed
// verbatim, so a client's own EDNS0 still works against the upstream.
//
// Isolation matches internal/netmon: this package imports neither web nor kea;
// the zone contents are pushed in by the owner (SetZone) and everything else is
// self-contained.
package dns

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Mode selects how a running listener set answers.
type Mode int

const (
	// ModeRedirect answers every A query with the listener's own bind address -
	// the captive-portal behavior for FACTORY/ONBOARDING.
	ModeRedirect Mode = iota
	// ModeZone serves the device zones authoritatively and forwards everything
	// else upstream (SERVFAIL when isolated).
	ModeZone
)

// redirectTTL matches the old onboarding redirector's 60s answers.
const redirectTTL = 60

// forwardTimeout bounds one upstream exchange; queryLimitPerSec is the
// per-source response rate limit; maxInflightForwards bounds the forward
// worker pool - beyond it the server sheds with SERVFAIL instead of spawning
// per packet.
const (
	forwardTimeout      = 3 * time.Second
	queryLimitPerSec    = 100
	maxInflightForwards = 16
)

// dohCanary is Firefox's use-application-dns.net probe: answering NXDOMAIN
// tells the browser to keep using local DNS instead of switching to DoH.
const dohCanary = "use-application-dns.net"

// Server owns the port-53 listeners. Start* is idempotent (stops any prior
// listener set first); the zone is swapped atomically and independently of the
// listener lifecycle.
type Server struct {
	zone atomic.Pointer[Zone]

	resolv     *resolvCache
	forwardSem chan struct{}
	limiter    rateLimiter

	mu        sync.Mutex
	listeners []*listener
	bindSet   map[string]bool // current bind IPs, excluded from upstream candidates
}

// New builds a stopped server. resolvPath overrides /etc/resolv.conf ("" for
// the default; tests point it at a fixture).
func New(resolvPath string) *Server {
	return &Server{
		resolv:     newResolvCache(resolvPath),
		forwardSem: make(chan struct{}, maxInflightForwards),
		limiter:    rateLimiter{counts: map[string]int{}},
	}
}

// SetZone atomically swaps the zone the ModeZone listeners answer from. Safe
// at any time, including while stopped or in redirect mode.
func (s *Server) SetZone(z *Zone) { s.zone.Store(z) }

// StartRedirect (re)starts captive-redirect listeners on the given addresses.
func (s *Server) StartRedirect(bindIPs []string) { s.start(ModeRedirect, bindIPs) }

// StartZone (re)starts authoritative+forwarder listeners on the given
// addresses - one socket per served-interface IP, so each apex answer names
// the address reachable from that listener's own segment.
func (s *Server) StartZone(bindIPs []string) { s.start(ModeZone, bindIPs) }

// start replaces the listener set. Each bind is best-effort: a failed bind
// (missing capability, interface not up yet) is logged and skipped rather than
// taking the others down - DNS is a feature, never a reason to fail an apply.
func (s *Server) start(mode Mode, bindIPs []string) {
	s.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindSet = make(map[string]bool, len(bindIPs))
	for _, ip := range bindIPs {
		if ip == "" {
			continue
		}
		l, err := newListener(s, mode, ip)
		if err != nil {
			log.Printf("[dns] listener on %s:53 not started: %v", ip, err)
			continue
		}
		s.listeners = append(s.listeners, l)
		s.bindSet[ip] = true
		l.wg.Add(1) // before the goroutine, so a fast stop() cannot Wait() past it
		go l.serve()
	}
}

// Stop tears down all listeners. Idempotent.
func (s *Server) Stop() {
	s.mu.Lock()
	listeners := s.listeners
	s.listeners, s.bindSet = nil, nil
	s.mu.Unlock()
	for _, l := range listeners {
		l.stop()
	}
}

// bindSetSnapshot returns the current bind-IP set for upstream exclusion.
func (s *Server) bindSetSnapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bindSet
}

// listener is one bound socket. Its mode and own address are fixed at start;
// per-socket state is what makes the apex answer segment-correct.
type listener struct {
	srv    *Server
	mode   Mode
	conn   *net.UDPConn
	bindIP [4]byte
	quit   chan struct{}
	wg     sync.WaitGroup
}

func newListener(srv *Server, mode Mode, bindIP string) (*listener, error) {
	ip4 := net.ParseIP(bindIP).To4()
	if ip4 == nil {
		return nil, &net.AddrError{Err: "not an IPv4 address", Addr: bindIP}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip4, Port: 53})
	if err != nil {
		return nil, err
	}
	l := &listener{srv: srv, mode: mode, conn: conn, quit: make(chan struct{})}
	copy(l.bindIP[:], ip4)
	log.Printf("[dns] listening on %s:53 (mode %d)", bindIP, mode)
	return l, nil
}

func (l *listener) stop() {
	close(l.quit)
	_ = l.conn.Close()
	l.wg.Wait()
}

func (l *listener) serve() {
	defer l.wg.Done()
	buf := make([]byte, 1500)
	for {
		// Shutdown is observed via the read error Close() forces; a leading
		// select would never fire while ReadFromUDP blocks.
		n, remote, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.quit:
				return
			default:
				// Backoff so a persistent error (ENETDOWN on a flapping link)
				// cannot spin this loop at full CPU.
				log.Printf("[dns] read error on %s: %v", l.conn.LocalAddr(), err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		if !l.srv.limiter.allow(remote.IP.String(), time.Now()) {
			continue // over the per-source rate: drop, never amplify
		}
		resp, forward := l.handle(buf[:n])
		if forward != nil {
			l.forwardAsync(forward, remote)
			continue
		}
		if resp != nil {
			_, _ = l.conn.WriteToUDP(resp, remote)
		}
	}
}

// handle answers a query locally, or returns a copy of the packet for the
// forward path (copied because the read buffer is reused). A nil,nil return
// drops the packet.
func (l *listener) handle(req []byte) (resp, forward []byte) {
	if len(req) >= headerLen && req[2]&0x80 != 0 {
		return nil, nil // a response, not a query - drop (anti-loop)
	}
	q, ok := parseQuestion(req)
	if !ok {
		return nil, nil
	}
	if q.Class != classIN {
		return respond(req, q, rcodeRefused, false), nil
	}

	if l.mode == ModeRedirect {
		if q.Type == typeA || q.Type == typeANY {
			return respond(req, q, rcodeNoError, false, rrA(l.bindIP, redirectTTL)), nil
		}
		return respond(req, q, rcodeNoError, false), nil
	}

	// Firefox DoH canary: NXDOMAIN keeps the browser on local DNS, so device
	// names stay resolvable.
	if q.Name == dohCanary || hasParent(q.Name, dohCanary) {
		return respond(req, q, rcodeNXDomain, true), nil
	}

	// Appliance apex: answered per-socket with this listener's own address, so
	// clients on every segment get the address they can actually reach.
	if q.Name == SuffixDHCP {
		if q.Type == typeA || q.Type == typeANY {
			return respond(req, q, rcodeNoError, true, rrA(l.bindIP, answerTTL)), nil
		}
		return respond(req, q, rcodeNoError, true), nil
	}

	zone := l.srv.zone.Load()
	if inZone(q.Name) {
		if zone != nil {
			if ip, hit := zone.a[q.Name]; hit {
				if q.Type == typeA || q.Type == typeANY {
					return respond(req, q, rcodeNoError, true, rrA(ip, answerTTL)), nil
				}
				return respond(req, q, rcodeNoError, true), nil // exists, no data of that type
			}
		}
		if q.Name == SuffixInv {
			return respond(req, q, rcodeNoError, true), nil // apex exists, carries no records
		}
		return respond(req, q, rcodeNXDomain, true), nil
	}

	if q.Type == typePTR && zone != nil {
		if ip, rev := reverseName(q.Name); rev {
			if target, hit := zone.ptr[ip]; hit {
				return respond(req, q, rcodeNoError, true, rrPTR(target, answerTTL)), nil
			}
		}
	}

	// Everything else goes upstream on the bounded forward path.
	cp := make([]byte, len(req))
	copy(cp, req)
	return nil, cp
}

// forwardAsync runs one upstream exchange on the bounded worker pool. When the
// pool is saturated the query is answered SERVFAIL immediately - shed, never a
// goroutine per packet.
func (l *listener) forwardAsync(req []byte, remote *net.UDPAddr) {
	q, ok := parseQuestion(req)
	if !ok {
		return
	}
	select {
	case l.srv.forwardSem <- struct{}{}:
	default:
		_, _ = l.conn.WriteToUDP(respond(req, q, rcodeServFail, false), remote)
		return
	}
	go func() {
		defer func() { <-l.srv.forwardSem }()
		resp := l.srv.forward(req, q)
		if resp == nil {
			resp = respond(req, q, rcodeServFail, false)
		}
		_, _ = l.conn.WriteToUDP(resp, remote)
	}()
}

// forward relays the query verbatim to each upstream in turn and returns the
// first verified reply, or nil when isolated / every upstream failed. Each
// attempt uses a fresh socket - a fresh kernel-chosen random source port per
// query - and only accepts a reply whose transaction id AND question match.
func (s *Server) forward(req []byte, q question) []byte {
	for _, up := range s.resolv.upstreams(s.bindSetSnapshot()) {
		if resp := forwardOne(req, q, net.JoinHostPort(up, "53")); resp != nil {
			return resp
		}
	}
	return nil
}

func forwardOne(req []byte, q question, upstream string) []byte {
	conn, err := net.Dial("udp", upstream)
	if err != nil {
		return nil
	}
	defer conn.Close()
	deadline := time.Now().Add(forwardTimeout)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(req); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if err != nil {
			return nil
		}
		if n < headerLen || buf[0] != req[0] || buf[1] != req[1] || buf[2]&0x80 == 0 {
			continue // wrong txid / not a response: keep reading until deadline
		}
		rq, ok := parseQuestion(buf[:n])
		if !ok || rq.Name != q.Name || rq.Type != q.Type || rq.Class != q.Class {
			continue // question mismatch: a spoof or a stale reply
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		return resp
	}
	return nil
}

// rateLimiter is a per-source fixed-window counter: cheap, deterministic, and
// self-cleaning (the map resets every window, so it cannot grow unbounded).
type rateLimiter struct {
	mu     sync.Mutex
	window int64
	counts map[string]int
}

func (r *rateLimiter) allow(source string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if w := now.Unix(); w != r.window {
		r.window = w
		clear(r.counts)
	}
	r.counts[source]++
	return r.counts[source] <= queryLimitPerSec
}

// hasParent reports whether name is a subdomain of parent.
func hasParent(name, parent string) bool {
	return len(name) > len(parent)+1 && name[len(name)-len(parent):] == parent && name[len(name)-len(parent)-1] == '.'
}
