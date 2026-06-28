package web

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// loginThrottle is a per-source-IP escalating backoff on failed logins. It is
// throttle-only by design: it never hard-locks an account, because a single-admin
// appliance must not be lockable by an attacker spamming the admin's username.
// Each consecutive failure from an IP pushes that IP's next-allowed time further
// out; a request arriving before nextAllowed is rejected immediately (no goroutine
// is held sleeping, which would itself be a DoS vector). A successful login clears
// the IP. State is in-memory (cleared on restart), which is fine for this box.
//
// The key is the raw RemoteAddr host: X-Forwarded-For is deliberately NOT trusted
// (it is client-settable). Behind a localhost reverse proxy (Caddy) every login
// then shares the 127.0.0.1 bucket - a global throttle, which still slows a brute
// force and, being throttle-only, never locks the real admin out.
type loginThrottle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry
	now     func() time.Time // injectable for tests
}

type throttleEntry struct {
	fails       int
	nextAllowed time.Time
	last        time.Time
}

const (
	// loginFreebies is how many failures an IP gets before backoff kicks in, so a
	// fat-fingered admin isn't delayed.
	loginFreebies = 3
	// loginBackoffCap bounds the escalating delay.
	loginBackoffCap = 30 * time.Second
	// loginEntryTTL is how long an idle IP entry is kept before pruning.
	loginEntryTTL = 15 * time.Minute
	// loginAuditAt is the consecutive-failure count at which a noisy IP is
	// audit-logged once (so a sustained attack leaves a trail without spamming).
	loginAuditAt = 8
)

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{entries: map[string]*throttleEntry{}, now: time.Now}
}

// allow reports whether an attempt from ip may proceed now; retryIn is the
// remaining wait when blocked.
func (t *loginThrottle) allow(ip string) (ok bool, retryIn time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[ip]
	if e == nil {
		return true, 0
	}
	if now := t.now(); now.Before(e.nextAllowed) {
		return false, e.nextAllowed.Sub(now)
	}
	return true, 0
}

// fail records a failed attempt from ip and returns the new consecutive-failure
// count (so the caller can decide whether to audit-log).
func (t *loginThrottle) fail(ip string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.pruneLocked(now)
	e := t.entries[ip]
	if e == nil {
		e = &throttleEntry{}
		t.entries[ip] = e
	}
	e.fails++
	e.last = now
	e.nextAllowed = now.Add(backoffFor(e.fails))
	return e.fails
}

// succeed clears any backoff for ip after a successful login.
func (t *loginThrottle) succeed(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, ip)
}

// backoffFor returns the delay applied after `fails` consecutive failures: 0 for
// the first loginFreebies, then doubling (1s, 2s, 4s, ...) capped at
// loginBackoffCap.
func backoffFor(fails int) time.Duration {
	if fails <= loginFreebies {
		return 0
	}
	shift := fails - loginFreebies - 1
	if shift >= 31 { // guard the shift from overflowing
		return loginBackoffCap
	}
	d := time.Second << shift
	if d > loginBackoffCap || d <= 0 {
		return loginBackoffCap
	}
	return d
}

// pruneLocked drops entries idle past loginEntryTTL so the map can't grow
// unbounded under a varied-source attack. Caller holds t.mu.
func (t *loginThrottle) pruneLocked(now time.Time) {
	for ip, e := range t.entries {
		if now.Sub(e.last) > loginEntryTTL {
			delete(t.entries, ip)
		}
	}
}

// clientIP extracts the source IP (host part) from r.RemoteAddr. Behind the Caddy
// reverse proxy the app binds loopback, so RemoteAddr is always 127.0.0.1 - which would
// make the login throttle GLOBAL (one bad attempt locks everyone out). When the immediate
// peer is loopback (the trusted proxy), read the real client from X-Forwarded-For.
//
// Use the RIGHT-MOST hop, not the left-most: a proxy appends the connecting peer to
// the right of XFF, so the right-most entry is the address the trusted proxy itself
// observed, while any left-most entries can be forged by the client. Our Caddy strips
// client-supplied XFF today (no trusted_proxies configured), but reading right-most keeps
// the per-IP throttle un-spoofable even if the proxy is later switched to append mode.
func clientIP(r *http.Request) string {
	if isLoopbackRemote(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			last := xff
			if i := strings.LastIndexByte(xff, ','); i >= 0 {
				last = xff[i+1:]
			}
			if last = strings.TrimSpace(last); last != "" {
				return last
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
