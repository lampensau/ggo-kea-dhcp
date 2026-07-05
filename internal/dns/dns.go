// Package dns is the appliance's single owner of UDP port 53 in ACTIVE: the
// authoritative server for the device zones inv.greengo.digital and
// dhcp.greengo.digital plus a deliberately dumb forwarder to the uplink's
// resolver. One component, never two servers racing for the socket. Outside
// ACTIVE the listeners are simply stopped (no DNS during FACTORY/ONBOARDING).
//
// Transport stance, decided and deliberate: UDP only. Answers are minimal
// single-record responses for a fleet of at most hundreds of names, so they
// always fit the classic 512-byte payload; anything that somehow would not gets
// the TC bit and no TCP listener to fall back to. No EDNS0 is negotiated for
// the server's own answers either. Forwarded queries and replies are relayed
// verbatim so a client's own EDNS0 still works against the upstream, except that
// a reply over 512 bytes to a client that did not signal EDNS0 is truncated with
// TC rather than reflected - together with a global forward-rate ceiling, that
// keeps the LAN-only forwarder from being used as an amplifier.
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

// forwardTimeout bounds one upstream exchange; queryLimitPerSec is the
// per-source response rate limit; maxInflightForwards bounds the forward
// worker pool - beyond it the server sheds with SERVFAIL instead of spawning
// per packet.
const (
	forwardTimeout      = 3 * time.Second
	queryLimitPerSec    = 100
	maxInflightForwards = 16
	// maxForwardsPerSec caps the forward path globally, across all sources. The
	// per-source limiter is trivially defeated by spoofed source IPs, so this
	// ceiling - not the per-source one - is what bounds how much the box will
	// relay out its uplink under a reflection flood. A real show LAN stays well
	// below it.
	maxForwardsPerSec = 200
)

// dohCanary is Firefox's use-application-dns.net probe: answering NXDOMAIN
// tells the browser to keep using local DNS instead of switching to DoH.
const dohCanary = "use-application-dns.net"

// Server owns the port-53 listeners. Start* is idempotent (stops any prior
// listener set first); the zone is swapped atomically and independently of the
// listener lifecycle.
type Server struct {
	zone       atomic.Pointer[Zone]
	servedNets atomic.Pointer[[]*net.IPNet] // subnets we answer PTR for authoritatively

	resolv     *resolvCache
	forwardSem chan struct{}
	limiter    rateLimiter
	fwdGate    forwardGate

	mu        sync.Mutex
	listeners []*listener
	bindSet   map[string]bool // current bind IPs, excluded from upstream candidates
	desired   []string        // IPs the last StartZone asked for, for RebindMissing
	// port is the listen port, 53 in production. A field only so tests can bind an
	// unprivileged port; nothing outside tests changes it.
	port int
}

// New builds a stopped server. resolvPath overrides /etc/resolv.conf ("" for
// the default; tests point it at a fixture).
func New(resolvPath string) *Server {
	return &Server{
		resolv:     newResolvCache(resolvPath),
		forwardSem: make(chan struct{}, maxInflightForwards),
		limiter:    rateLimiter{counts: map[string]int{}},
		port:       53,
	}
}

// SetZone atomically swaps the zone the listeners answer from. Safe at any time,
// including while stopped.
func (s *Server) SetZone(z *Zone) { s.zone.Store(z) }

// SetServedSubnets records the subnets the box is authoritative for in reverse,
// so a PTR query for an address inside one is answered here (NXDOMAIN on a miss)
// instead of leaking upstream. Unparseable CIDRs are skipped. Safe at any time.
func (s *Server) SetServedSubnets(cidrs []string) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	s.servedNets.Store(&nets)
}

// servesReverse reports whether ip falls in a subnet the box serves.
func (s *Server) servesReverse(ip [4]byte) bool {
	nets := s.servedNets.Load()
	if nets == nil {
		return false
	}
	addr := net.IP(ip[:])
	for _, n := range *nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// StartZone (re)starts authoritative+forwarder listeners on the given addresses -
// one socket per served-interface IP, so each apex answer names the address
// reachable from that listener's own segment. It returns the addresses whose bind
// failed so the caller can surface them; an empty return means every listener came
// up. Each bind is a single attempt (no sleep): an address that is not yet present
// after a re-IP is left to RebindMissing, the caller's sampler-driven self-heal,
// so StartZone is fast enough to run inline in the reconcile.
func (s *Server) StartZone(bindIPs []string) []string { return s.start(bindIPs) }

// start replaces the listener set. Each bind is best-effort: a failed bind
// (missing capability, interface not up yet) is logged and skipped rather than
// taking the others down - DNS is a feature, never a reason to fail an apply.
// The failed addresses are returned for the caller to audit.
func (s *Server) start(bindIPs []string) []string {
	s.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindSet = make(map[string]bool, len(bindIPs))
	s.desired = s.desired[:0]
	var failed []string
	for _, ip := range bindIPs {
		if ip == "" {
			continue
		}
		s.desired = append(s.desired, ip)
		l, err := newListener(s, ip)
		if err != nil {
			log.Printf("[dns] listener on %s:53 not started: %v", ip, err)
			failed = append(failed, ip)
			continue
		}
		s.listeners = append(s.listeners, l)
		s.bindSet[ip] = true
		l.wg.Add(1) // before the goroutine, so a fast stop() cannot Wait() past it
		go l.serve()
	}
	return failed
}

// RebindMissing re-attempts a bind for every desired address that is not currently
// listening - the self-heal for an address that was not yet present when StartZone
// ran (its single bind attempt failed) but has since appeared on the interface.
// Without this a scope whose bind lost the post-re-IP race stays dark until the next
// full reconcile, even though the address is now up and the zone content refreshes
// every sampler tick. One attempt per address (the caller's sampler cadence is the
// retry interval, so no inner sleep); a still-absent address just fails ListenUDP and
// is left for the next call. Returns the addresses that newly bound, so the caller can
// audit the recovery. Inert when the server is stopped (no desired set).
func (s *Server) RebindMissing() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bindSet == nil {
		return nil // stopped: never resurrect a deliberately torn-down listener set
	}
	var healed []string
	for _, ip := range s.desired {
		if s.bindSet[ip] {
			continue
		}
		l, err := newListener(s, ip)
		if err != nil {
			continue // still absent / still failing: leave it for the next tick
		}
		s.listeners = append(s.listeners, l)
		s.bindSet[ip] = true
		l.wg.Add(1) // before the goroutine, so a fast stop() cannot Wait() past it
		go l.serve()
		healed = append(healed, ip)
	}
	return healed
}

// Stop tears down all listeners. Idempotent.
func (s *Server) Stop() {
	s.mu.Lock()
	listeners := s.listeners
	s.listeners, s.bindSet, s.desired = nil, nil, nil
	s.mu.Unlock()
	for _, l := range listeners {
		l.stop()
	}
}

// bindSetSnapshot returns a copy of the current bind-IP set for upstream
// exclusion. It must be a copy: the caller reads it unlocked on the forward path
// while RebindMissing/start mutate the live map under s.mu, and a shared reference
// would be a concurrent map read+write (a fatal runtime throw).
func (s *Server) bindSetSnapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bindSet == nil {
		return nil
	}
	out := make(map[string]bool, len(s.bindSet))
	for ip := range s.bindSet {
		out[ip] = true
	}
	return out
}

// listener is one bound socket. Its own address is fixed at start; per-socket
// state is what makes the apex answer segment-correct.
type listener struct {
	srv    *Server
	conn   *net.UDPConn
	bindIP [4]byte
	quit   chan struct{}
	wg     sync.WaitGroup
}

func newListener(srv *Server, bindIP string) (*listener, error) {
	ip4 := net.ParseIP(bindIP).To4()
	if ip4 == nil {
		return nil, &net.AddrError{Err: "not an IPv4 address", Addr: bindIP}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip4, Port: srv.port})
	if err != nil {
		return nil, err
	}
	l := &listener{srv: srv, conn: conn, quit: make(chan struct{})}
	copy(l.bindIP[:], ip4)
	log.Printf("[dns] listening on %s:53", bindIP)
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
	// Only standard QUERY (opcode 0) is implemented; IQUERY/STATUS/NOTIFY/UPDATE
	// get NOTIMP rather than being mishandled as a query.
	if opcode := (req[2] >> 3) & 0x0f; opcode != 0 {
		return respond(req, q, rcodeNotImp, false), nil
	}
	if q.Class != classIN {
		return respond(req, q, rcodeRefused, false), nil
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

	if q.Type == typePTR {
		if ip, rev := reverseName(q.Name); rev {
			if zone != nil {
				if target, hit := zone.ptr[ip]; hit {
					return respond(req, q, rcodeNoError, true, rrPTR(target, answerTTL)), nil
				}
			}
			// A reverse query for an address in a subnet the box serves is ours to
			// answer: NXDOMAIN on a miss, never forwarded. This keeps RFC1918 PTRs
			// (e.g. 10.in-addr.arpa) from leaking upstream and from burning the
			// forward timeout per miss when the box is isolated.
			if l.srv.servesReverse(ip) {
				return respond(req, q, rcodeNXDomain, true), nil
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
	if !l.srv.fwdGate.allow(time.Now()) {
		return // over the global forward ceiling: drop, never reflect
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
		switch {
		case resp == nil:
			resp = respond(req, q, rcodeServFail, false)
		case len(resp) > maxUDPResponse && arCount(req) == 0:
			// The request carried no additional records (a cheap proxy for "no
			// EDNS0", see arCount), so the client is bound to 512 bytes; relaying
			// a large upstream answer verbatim would make the box an amplifier.
			// Truncate to the question with TC set - the same UDP-only stance as
			// our own answers. The global forward ceiling is the real defense;
			// this just avoids reflecting an oversized reply to a classic client.
			resp = respond(req, q, rcodeNoError, false)
			resp[2] |= 0x02 // TC
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

// arCount reads the ARCOUNT header field. arCount==0 means the request carried no
// additional records at all - a cheap proxy for "no EDNS0 OPT record", not a true
// OPT-record parse (a request could in principle carry a non-OPT additional
// record). It only gates whether an oversized upstream reply is truncated to 512
// bytes; the global forward ceiling is the actual anti-amplification defense. req
// is always at least a full header here (parseQuestion ran).
func arCount(req []byte) int {
	return int(req[10])<<8 | int(req[11])
}

// forwardGate is a global fixed-window rate cap on the forward path, across all
// sources - the ceiling the per-source limiter cannot provide once source IPs
// are spoofed.
type forwardGate struct {
	mu     sync.Mutex
	window int64
	count  int
}

func (g *forwardGate) allow(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if w := now.Unix(); w != g.window {
		g.window, g.count = w, 0
	}
	g.count++
	return g.count <= maxForwardsPerSec
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
