package web

import (
	"sync"
	"testing"
)

// TestLastSeenTrackerThrottlesWrites pins the write-throttle policy: the in-memory
// view follows every observation, but a row is only re-persisted once cltt has
// advanced lastSeenAdvance past what was last written. The two conditions are
// independent, and inverting either one is invisible at the call site - the sampler
// just writes the Pi's SD card every 12s, or stops writing at all.
func TestLastSeenTrackerThrottlesWrites(t *testing.T) {
	tr := newLastSeenTracker()

	// First sighting of an identity always persists: written[id] is 0, so any
	// positive cltt clears the advance.
	pending := tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 1000}})
	if len(pending) != 1 {
		t.Fatalf("first sighting must persist: got %d pending rows, want 1", len(pending))
	}
	if got := pending["aa"]; got.Identity != "aa" || got.Kind != "lease" || got.LastSeen != 1000 {
		t.Fatalf("pending row mis-built: %+v", got)
	}

	// A sub-threshold advance updates the display map but writes nothing.
	pending = tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 1000 + lastSeenAdvance - 1}})
	if len(pending) != 0 {
		t.Fatalf("advance below lastSeenAdvance must not persist: got %d pending rows", len(pending))
	}
	if got := tr.snapshot()["aa"]; got != 1000+lastSeenAdvance-1 {
		t.Fatalf("seen must track every observation regardless of the write throttle: got %d", got)
	}

	// Exactly at the threshold, measured from the last WRITTEN value (1000), not the
	// last seen one - so the throttle can't be defeated by a drip of sub-threshold
	// samples.
	pending = tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 1000 + lastSeenAdvance}})
	if len(pending) != 1 {
		t.Fatalf("advance of exactly lastSeenAdvance must persist: got %d pending rows", len(pending))
	}

	// A stale (out-of-order) sample must not roll the display value backwards.
	tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 500}})
	if got := tr.snapshot()["aa"]; got != 1000+lastSeenAdvance {
		t.Fatalf("a stale cltt rolled seen backwards to %d", got)
	}
}

// TestLastSeenTrackerPrimeSuppressesRewrite covers the restart path: prime fills both
// maps, so the first sample after a reboot re-persists nothing it already has.
func TestLastSeenTrackerPrimeSuppressesRewrite(t *testing.T) {
	tr := newLastSeenTracker()
	tr.prime(map[string]int64{"aa": 5000})

	if pending := tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 5000}}); len(pending) != 0 {
		t.Fatalf("a primed identity re-observed at its persisted cltt must not rewrite: got %d rows", len(pending))
	}
	if pending := tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 5000 + lastSeenAdvance}}); len(pending) != 1 {
		t.Fatalf("a primed identity advancing past the threshold must persist: got %d rows", len(pending))
	}

	// reset drops history so a factory wipe cannot be repopulated from stale memory.
	tr.reset()
	if got := tr.snapshot(); len(got) != 0 {
		t.Fatalf("reset must clear seen: %v", got)
	}
	if pending := tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 5000}}); len(pending) != 1 {
		t.Fatal("after reset the next sighting must persist again (written was cleared too)")
	}
}

// TestLastSeenTrackerSnapshotIsACopy proves a page render cannot mutate the tracker's
// live map through the snapshot it holds while the sampler keeps writing.
func TestLastSeenTrackerSnapshotIsACopy(t *testing.T) {
	tr := newLastSeenTracker()
	tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: 1000}})

	snap := tr.snapshot()
	snap["aa"] = 1
	delete(snap, "aa")

	if got := tr.snapshot()["aa"]; got != 1000 {
		t.Fatalf("snapshot aliased the tracker's map: got %d, want 1000", got)
	}
}

// TestLastSeenTrackerConcurrentRecordAndSnapshot runs the sampler's write path against
// the render read path, the interleaving the mutex exists for. It asserts nothing
// directly: the race detector is the assertion, so this test only earns its keep under
// `go test -race` (which CI and the make gate both run).
func TestLastSeenTrackerConcurrentRecordAndSnapshot(t *testing.T) {
	tr := newLastSeenTracker()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 200 {
			tr.record([]lastSeenObs{{identity: "aa", kind: "lease", cltt: int64(i) * lastSeenAdvance}})
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			_ = tr.snapshot()["aa"]
		}
	}()
	wg.Wait()
}
