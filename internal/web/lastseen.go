package web

import (
	"maps"
	"sync"

	"ggo-kea-dhcp/internal/db"
)

// lastSeenAdvance is the minimum cltt advance (seconds) before a last_seen row is
// re-persisted. cltt only moves on a renewal (infrequent), so this collapses the
// steady state to ~zero SQLite writes between renewals - the in-memory map still
// tracks every sample for display.
const lastSeenAdvance = 60

// lastSeenObs is one "identity was active at cltt" observation the sampler feeds the
// tracker; kind is the last_seen row's kind column ("lease" or "port").
type lastSeenObs struct {
	identity string
	kind     string
	cltt     int64
}

// lastSeenTracker tracks when each identity (normalized MAC for leases, flex-id key
// for switch ports) was last observed active, so a pinned-but-offline port / offline
// reservation can show "last active 3d ago". seen is the freshest in-memory view
// (updated every metrics sample from lease cltt); written mirrors what has been
// persisted to SQLite so the sampler only writes on a meaningful advance (the Pi's
// SD card is write-sensitive). Both are primed from SQLite at startup.
type lastSeenTracker struct {
	mu      sync.RWMutex
	seen    map[string]int64
	written map[string]int64
}

func newLastSeenTracker() *lastSeenTracker {
	return &lastSeenTracker{seen: map[string]int64{}, written: map[string]int64{}}
}

// prime loads persisted last-seen values into both maps so a restart doesn't lose
// history or re-write every row on the first sample.
func (t *lastSeenTracker) prime(ls map[string]int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range ls {
		t.seen[k] = v
		t.written[k] = v
	}
}

// reset drops the in-memory tracker so it doesn't repopulate a wiped table from
// stale memory on the next sample (called after a factory wipe).
func (t *lastSeenTracker) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen = map[string]int64{}
	t.written = map[string]int64{}
}

// snapshot returns a copy of the freshest last-seen map (identity -> epoch) for the
// page builders, so a render never holds the lock or races the sampler.
func (t *lastSeenTracker) snapshot() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return maps.Clone(t.seen)
}

// record folds a batch of observations into the tracker: seen always takes the
// freshest value; the returned pending map holds only identities whose cltt advanced
// past what was last persisted (lastSeenAdvance), for the caller to UpsertLastSeen
// outside the lock. The lock is released via defer even if this panics: record runs
// under the sampler's panic recovery (sampleOnceSafe), and a lock left held would
// wedge every later tick and page render (all of which take this lock), turning a
// recoverable panic into a UI-wide deadlock.
func (t *lastSeenTracker) record(obs []lastSeenObs) map[string]db.LastSeen {
	pending := make(map[string]db.LastSeen)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, o := range obs {
		if o.cltt > t.seen[o.identity] {
			t.seen[o.identity] = o.cltt
		}
		if o.cltt-t.written[o.identity] >= lastSeenAdvance {
			t.written[o.identity] = o.cltt
			pending[o.identity] = db.LastSeen{Identity: o.identity, Kind: o.kind, LastSeen: o.cltt}
		}
	}
	return pending
}
