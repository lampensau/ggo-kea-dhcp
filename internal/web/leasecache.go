package web

import (
	"context"
	"errors"
	"sync"
	"time"

	"ggo-kea-dhcp/internal/kea"
)

// leaseSrcTTL is the freshness window the read-through consumers accept. Kept
// below the live ticker's 4s cadence so every ticker poll is a real refresh
// that the other cadences (netmon feed, arp/ggoscan IP feed, DNS zone prime,
// search keystrokes, SSE connect snapshots) then ride for free.
const leaseSrcTTL = 3 * time.Second

// defaultLeasePageSize is the page size for a full lease dump from Kea. Well above
// any real fleet on one appliance, so a single page returns every active lease.
const defaultLeasePageSize = 1000

// leaseCache is the shared short-TTL Kea lease provider. The background
// cadences and display paths that used to each run their own GetLeases against
// the control socket read through this one cache, collapsing four-plus
// uncoordinated polling loops into at most one round-trip per freshness window
// - and giving every view the same snapshot instead of four slightly-diverged
// ones. Single-flight: concurrent callers during a refresh wait for and share
// the one round-trip.
//
// The returned slice is SHARED - callers must treat it as read-only (every
// existing consumer copies/filters into its own rows; none sorts or mutates
// the lease slice in place).
type leaseCache struct {
	fetch func(ctx context.Context) ([]kea.ActiveLease, error)
	now   func() time.Time // injectable for tests

	mu       sync.Mutex
	leases   []kea.ActiveLease
	err      error
	at       time.Time
	inflight chan struct{} // non-nil while a fetch runs; closed when it lands
}

func newLeaseCache(fetch func(ctx context.Context) ([]kea.ActiveLease, error)) *leaseCache {
	return &leaseCache{fetch: fetch, now: time.Now}
}

// getLeases reads the lease set through the shared provider. A Server built
// without NewServer (unit tests wiring only the fields they need) has no
// provider and falls back to a direct fetch - mirroring metricsStore's
// nil-tolerant snapshot.
func (s *Server) getLeases(ctx context.Context, maxAge time.Duration) ([]kea.ActiveLease, error) {
	if s.leaseSrc == nil {
		return s.kea.GetLeases(ctx, defaultLeasePageSize)
	}
	return s.leaseSrc.get(ctx, maxAge)
}

// get returns the lease set no older than maxAge. maxAge 0 forces a poll: the
// metrics sampler primes the Kea RTT and health signal from its own real
// round-trip, and the event-driven publishes must see post-mutation state. A
// forced caller never joins an in-flight fetch (which may predate its mutation);
// it waits that fetch out and leads its own. Errors age like results, so a Kea
// outage yields one shared failure per window instead of a per-caller retry stampede.
func (c *leaseCache) get(ctx context.Context, maxAge time.Duration) ([]kea.ActiveLease, error) {
	c.mu.Lock()
	if maxAge > 0 && !c.at.IsZero() && c.now().Sub(c.at) < maxAge {
		l, err := c.leases, c.err
		c.mu.Unlock()
		return l, err
	}
	// A forced caller (maxAge 0) publishes right after a mutation and must see a poll
	// dispatched AFTER that mutation, so it never joins an in-flight fetch - that fetch
	// may have been dispatched before the mutation and would report pre-mutation state.
	// It waits the in-flight fetch out and then leads its own fresh poll. A stale
	// non-forced reader has no such constraint and shares the in-flight poll (the
	// single-flight collapse #83 added). The loop re-checks after each wait: if another
	// forced caller started a new poll in the gap, wait that one out too.
	for wait := c.inflight; wait != nil; wait = c.inflight {
		c.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		c.mu.Lock()
		if maxAge > 0 {
			l, err := c.leases, c.err
			c.mu.Unlock()
			return l, err
		}
	}
	done := make(chan struct{})
	c.inflight = done
	c.mu.Unlock()

	// The store-and-release runs deferred so a PANICKING fetch cannot wedge the
	// cache: this is the single chokepoint for all lease reads, and an in-flight
	// marker left set would block every future read until its context expired.
	// err is pre-set so the panic path publishes an honest failure to the
	// waiters (never an empty success); the panic itself still unwinds to the
	// leader's own recover wrapper, and the aged error retries after the TTL.
	var leases []kea.ActiveLease
	err := errors.New("lease fetch did not complete")
	defer func() {
		c.mu.Lock()
		c.leases, c.err, c.at = leases, err, c.now()
		c.inflight = nil
		close(done)
		c.mu.Unlock()
	}()

	// The fetch runs under its own bound (opCtx), detached from the caller: a
	// canceled request must not poison the result every waiter shares.
	fctx, cancel := opCtx()
	defer cancel()
	leases, err = c.fetch(fctx)
	return leases, err
}
