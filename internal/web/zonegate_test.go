package web

import (
	"sync"
	"testing"
)

// TestZoneGateRefusesStaleGeneration pins the rule the type exists for: a rebuild that
// dispatched earlier (a slow detached primeDNSZone) must not land its staler zone over
// one a later dispatch already installed. Only the generation ordering decides, never
// the arrival order.
func TestZoneGateRefusesStaleGeneration(t *testing.T) {
	var g zoneGate

	early, late := g.nextGen(), g.nextGen()
	if early >= late {
		t.Fatalf("nextGen must be monotonic: %d then %d", early, late)
	}

	installed := 0
	if !g.tryApply(late, func() { installed++ }) {
		t.Fatal("the freshest generation must apply")
	}
	if g.tryApply(early, func() { installed++ }) {
		t.Fatal("a generation older than the last applied must be refused")
	}
	if installed != 1 {
		t.Fatalf("the stale install ran anyway: %d installs", installed)
	}

	// Re-applying the same generation is allowed (only strictly-older loses), so a
	// caller that re-runs its own dispatch is not silently dropped.
	if !g.tryApply(late, func() { installed++ }) {
		t.Fatal("re-applying the current generation must not be refused")
	}
	if installed != 2 {
		t.Fatalf("re-apply did not install: %d installs", installed)
	}
}

// TestZoneGateFirstDispatchApplies covers the zero value: appliedGen starts at 0 and
// nextGen counts from 1, so the very first rebuild installs without a special case.
// (There is deliberately no unversioned escape hatch: a gen-0 apply used to reset
// appliedGen, re-opening the staleness window this gate exists to close.)
func TestZoneGateFirstDispatchApplies(t *testing.T) {
	var g zoneGate

	installed := 0
	first := g.nextGen()
	if first != 1 {
		t.Fatalf("nextGen must count from 1, got %d", first)
	}
	if !g.tryApply(first, func() { installed++ }) {
		t.Fatal("the first dispatch must apply against a zero-value gate")
	}
	if installed != 1 {
		t.Fatal("the first dispatch did not install")
	}
}

// TestZoneGateSigLatch covers the sampler's idle-rebuild dedup: the signature only
// latches after a rebuild wins, so a rebuild that lost its generation race leaves the
// sig unlatched and the next tick retries instead of skipping forever.
func TestZoneGateSigLatch(t *testing.T) {
	var g zoneGate

	if !g.sigChanged(42) {
		t.Fatal("a fresh gate must report the first signature as changed")
	}
	g.latchSig(42)
	if g.sigChanged(42) {
		t.Fatal("the latched signature must read as unchanged (idle box: no rebuild)")
	}
	if !g.sigChanged(43) {
		t.Fatal("a different signature must read as changed")
	}
}

// TestZoneGateConcurrentApply runs competing dispatches under -race and asserts the
// gate serializes {check + install} - the winner is the highest generation, and no
// install overlaps another.
func TestZoneGateConcurrentApply(t *testing.T) {
	var g zoneGate

	var mu sync.Mutex
	var inFlight, maxInFlight int
	lastApplied := uint64(0)

	gens := make([]uint64, 16)
	for i := range gens {
		gens[i] = g.nextGen()
	}

	var wg sync.WaitGroup
	for _, gen := range gens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.tryApply(gen, func() {
				mu.Lock()
				inFlight++
				if inFlight > maxInFlight {
					maxInFlight = inFlight
				}
				if gen > lastApplied {
					lastApplied = gen
				}
				inFlight--
				mu.Unlock()
			})
		}()
	}
	wg.Wait()

	if maxInFlight != 1 {
		t.Fatalf("installs overlapped: %d concurrent - the gate must serialize check+install", maxInFlight)
	}
	if lastApplied != gens[len(gens)-1] {
		t.Fatalf("the newest generation never applied: last installed %d, newest %d", lastApplied, gens[len(gens)-1])
	}
}
