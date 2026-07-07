// Package dns is the appliance's single owner of UDP port 53 in ACTIVE: the
// authoritative server for the device zones inv.greengo.digital and
// dhcp.greengo.digital plus a deliberately dumb forwarder to the uplink's
// resolver. One component, never two servers racing for the socket. Outside
// ACTIVE the listeners are simply stopped (no DNS during FACTORY/ONBOARDING).
//
// Transport: UDP plus a TCP fallback (RFC 7766). The server's own answers are
// minimal single-record responses that always fit the classic 512-byte payload,
// but a forwarded upstream answer can exceed any UDP size (a large TXT or DNSSEC
// reply), and such an answer is only reachable over TCP - so the box listens on
// TCP/53 as well and forwards over TCP when a client retries there. Over UDP a
// reply larger than 512 bytes to a client that did not signal EDNS0 is still
// truncated with TC rather than reflected; TCP carries the full answer without
// truncation. A completed TCP handshake cannot be source-spoofed, so the TCP
// path is not a reflection vector; together with the global forward-rate ceiling
// and a bounded pool of concurrent TCP connections, the LAN-only forwarder still
// cannot be turned into an amplifier.
//
// Isolation matches internal/netmon: this package imports neither web nor kea;
// the zone contents are pushed in by the owner (SetZone) and everything else is
// self-contained.
package dns

import (
	"io"
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
	// tcpIdleTimeout bounds one TCP connection's read and write per RFC 7766 -
	// also the slowloris defense: a client that opens a connection and dribbles
	// (or never reads its answer) is dropped rather than holding state.
	tcpIdleTimeout = 5 * time.Second
	// maxTCPConns caps concurrent TCP connections across all listeners; beyond it
	// a newly accepted connection is closed immediately rather than served. TCP
	// answers are rare on a LAN (only replies over the UDP size), so this is
	// generous. ponytail: global cap, make it per-listener only if one segment
	// can ever starve another.
	maxTCPConns = 32
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
	tcpSem     chan struct{} // bounds concurrent TCP connections across all listeners
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
		tcpSem:     make(chan struct{}, maxTCPConns),
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
		l.startServing()
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
		l.startServing()
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
	tcpLn  *net.TCPListener // nil if the TCP bind failed (UDP still serves)
	bindIP [4]byte
	quit   chan struct{}
	wg     sync.WaitGroup

	mu      sync.Mutex
	closing bool                  // set by stop(); track() refuses new conns once true
	active  map[net.Conn]struct{} // open TCP conns, closed on stop for prompt shutdown
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
	// TCP is the RFC 7766 fallback for answers over the UDP size, but a failed TCP
	// bind must never take down the working UDP listener - so it is best-effort.
	if tcpLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip4, Port: srv.port}); err != nil {
		log.Printf("[dns] TCP listener on %s:53 not started (UDP only): %v", bindIP, err)
	} else {
		l.tcpLn = tcpLn
	}
	log.Printf("[dns] listening on %s:53", bindIP)
	return l, nil
}

// startServing launches the read loops for a freshly bound listener. The wg is
// incremented before each goroutine so a fast stop() cannot Wait() past it.
func (l *listener) startServing() {
	l.wg.Add(1)
	go l.serve()
	if l.tcpLn != nil {
		l.wg.Add(1)
		go l.serveTCP()
	}
}

func (l *listener) stop() {
	close(l.quit)
	_ = l.conn.Close()
	if l.tcpLn != nil {
		_ = l.tcpLn.Close()
	}
	// Close any in-flight TCP conns so a connection blocked in a read deadline
	// does not hold stop() for up to tcpIdleTimeout; closing set under the same
	// lock track() takes closes the accept-vs-stop race.
	l.mu.Lock()
	l.closing = true
	for c := range l.active {
		_ = c.Close()
	}
	l.mu.Unlock()
	l.wg.Wait()
}

// track registers an accepted TCP conn so stop() can close it. It returns false
// if stop() has already begun, in which case the caller must not start a handler
// (stop() would never join it).
func (l *listener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return false
	}
	if l.active == nil {
		l.active = make(map[net.Conn]struct{})
	}
	l.active[c] = struct{}{}
	return true
}

func (l *listener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.active, c)
	l.mu.Unlock()
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
			// Truncate to the question with TC set, matching the UDP path for our
			// own answers; a client that needs the full answer retries over TCP.
			// The global forward ceiling is the real defense; this just avoids
			// reflecting an oversized reply to a classic UDP client.
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
	// Full UDP-datagram sized: an upstream EDNS0 reply can exceed 4096 bytes, and a
	// short buffer would kernel-truncate the read into a malformed relay. forwardAsync
	// still applies the TC-set truncation for a non-EDNS0 (arCount==0) client.
	buf := make([]byte, 65535)
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

// serveTCP accepts TCP connections and dispatches each to a bounded worker. The
// shutdown and transient-error handling mirror the UDP serve loop.
func (l *listener) serveTCP() {
	defer l.wg.Done()
	for {
		conn, err := l.tcpLn.AcceptTCP()
		if err != nil {
			select {
			case <-l.quit:
				return
			default:
				log.Printf("[dns] tcp accept error on %s: %v", l.tcpLn.Addr(), err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		select {
		case l.srv.tcpSem <- struct{}{}:
		default:
			_ = conn.Close() // over the global TCP connection cap: shed
			continue
		}
		if !l.track(conn) { // racing a stop(): do not start a handler stop() will not join
			<-l.srv.tcpSem
			_ = conn.Close()
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer func() { <-l.srv.tcpSem }()
			defer l.untrack(conn)
			l.handleTCPConn(conn)
		}()
	}
}

// handleTCPConn serves length-framed queries on one connection until it goes idle
// or the peer closes it (RFC 7766 connection reuse). Queries run through the same
// handle() as UDP, so device zones / canary / PTR answer identically; a
// forwardable query is relayed over TCP without the UDP truncation.
func (l *listener) handleTCPConn(conn *net.TCPConn) {
	defer conn.Close()
	remote := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout)) // idle between queries
		req, ok := readTCPMessage(conn)
		if !ok {
			return // EOF, idle deadline, or a malformed frame
		}
		if !l.srv.limiter.allow(remote, time.Now()) {
			return // over the per-source rate: drop the connection
		}
		resp, forward := l.handle(req)
		if forward != nil {
			if resp = l.forwardTCP(forward); resp == nil {
				if q, ok := parseQuestion(req); ok {
					resp = respond(req, q, rcodeServFail, false)
				}
			}
		}
		if resp == nil {
			return // dropped query (e.g. a response sent to us): nothing to say
		}
		// Re-arm the deadline for the write: forwardTCP can burn seconds on a slow
		// or dead upstream, and a fetched answer must not fail the write because the
		// read deadline already lapsed.
		_ = conn.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
		if !writeTCPMessage(conn, resp) {
			return
		}
	}
}

// forwardTCP relays a forwardable query to each upstream over TCP and returns the
// first verified reply, or nil when isolated / over a ceiling / all upstreams
// failed. Unlike the UDP path it never truncates - TCP exists precisely to carry
// the large answer. It reuses the same forward ceiling and worker pool as UDP so
// TCP cannot sidestep the anti-amplification bounds.
func (l *listener) forwardTCP(req []byte) []byte {
	q, ok := parseQuestion(req)
	if !ok {
		return nil
	}
	if !l.srv.fwdGate.allow(time.Now()) {
		return nil // over the global forward ceiling
	}
	select {
	case l.srv.forwardSem <- struct{}{}:
	default:
		return nil // pool saturated: caller answers SERVFAIL
	}
	defer func() { <-l.srv.forwardSem }()
	for _, up := range l.srv.resolv.upstreams(l.srv.bindSetSnapshot()) {
		if resp := forwardOneTCP(req, q, net.JoinHostPort(up, "53")); resp != nil {
			return resp
		}
	}
	return nil
}

// forwardOneTCP performs one TCP exchange with an upstream: framed query, framed
// reply, verified by transaction id AND question like the UDP path. The whole
// exchange is bounded by forwardTimeout.
func forwardOneTCP(req []byte, q question, upstream string) []byte {
	conn, err := net.DialTimeout("tcp", upstream, forwardTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(forwardTimeout))
	if !writeTCPMessage(conn, req) {
		return nil
	}
	resp, ok := readTCPMessage(conn)
	if !ok {
		return nil
	}
	if len(resp) < headerLen || resp[0] != req[0] || resp[1] != req[1] || resp[2]&0x80 == 0 {
		return nil
	}
	rq, ok := parseQuestion(resp)
	if !ok || rq.Name != q.Name || rq.Type != q.Type || rq.Class != q.Class {
		return nil
	}
	return resp
}

// readTCPMessage reads one length-prefixed DNS message (RFC 7766 framing). The
// 2-byte prefix bounds the body to <=65535 inherently; the caller's read deadline
// bounds a peer that declares a length and then dribbles. ok=false on EOF,
// deadline, a short read, or a length too small to be a DNS message.
func readTCPMessage(r io.Reader) ([]byte, bool) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n < headerLen {
		return nil, false
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, false
	}
	return msg, true
}

// writeTCPMessage writes msg with its 2-byte length prefix in a single write. A
// message that cannot be framed (over 65535 bytes) is refused; our own answers
// are tiny and a forwarded upstream answer is already a valid <=65535 message.
func writeTCPMessage(w io.Writer, msg []byte) bool {
	if len(msg) > 0xffff {
		return false
	}
	framed := make([]byte, 2+len(msg))
	framed[0], framed[1] = byte(len(msg)>>8), byte(len(msg))
	copy(framed[2:], msg)
	_, err := w.Write(framed)
	return err == nil
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

// maxTrackedSources bounds the limiter's per-window source map (the same cap
// shape as the netmon presence maps): a spoofed-source flood otherwise grows
// it O(pps) within the second - and Go maps never release their buckets, so a
// single flood would inflate the map's footprint for the process lifetime.
// Sized generously above any real client population on a served LAN segment.
const maxTrackedSources = 512

// rateLimiter is a per-source fixed-window counter: cheap, deterministic, and
// bounded - the map resets every window and is capped within one. When the cap
// is hit, sources not already tracked are refused for the remainder of that
// window. Fail-closed is deliberate (fail-open would make the authoritative
// path a reflector), and honestly: under a SUSTAINED spoofed flood the slots
// refill with fakes at every window rollover, so legitimate clients that lose
// the race - device-name resolution included - are starved for the flood's
// whole duration, not one second. That is the accepted cost; the flood itself
// is already an outage condition on the segment. The cap budget is global
// across all listeners/VLANs, not per segment. capLogged edge-triggers one log
// line per capped WINDOW - it resets with the per-second rollover, so a
// sustained flood logs roughly once a second for its duration - keeping the
// starvation diagnosable without per-packet spam.
type rateLimiter struct {
	mu        sync.Mutex
	window    int64
	counts    map[string]int
	capLogged bool
}

func (r *rateLimiter) allow(source string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if w := now.Unix(); w != r.window {
		r.window = w
		r.capLogged = false
		clear(r.counts)
	}
	n, tracked := r.counts[source]
	if !tracked && len(r.counts) >= maxTrackedSources {
		if !r.capLogged {
			r.capLogged = true
			log.Printf("[dns] per-source limiter at cap (%d sources this second) - refusing untracked sources; likely a spoofed flood", maxTrackedSources)
		}
		return false
	}
	n++
	r.counts[source] = n
	return n <= queryLimitPerSec
}

// hasParent reports whether name is a subdomain of parent.
func hasParent(name, parent string) bool {
	return len(name) > len(parent)+1 && name[len(name)-len(parent):] == parent && name[len(name)-len(parent)-1] == '.'
}
