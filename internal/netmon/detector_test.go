package netmon

import (
	"testing"
	"time"
)

// at returns base + d, a terse way to build monotonically increasing instants.
func at(d time.Duration) time.Time { return base.Add(d) }

// TestPresenceConfirmAndAbsence walks a presence tracker through the full edge
// cycle: a sighting confirms immediately (confirmAfter 0), staying present while
// re-sighted, then absence after the timeout fires exactly one -1 transition.
func TestPresenceConfirmAndAbsence(t *testing.T) {
	p := newPresence(0, 30*time.Second)

	// No sightings yet → no transition, not present.
	if got := p.transition(at(0)); got != 0 {
		t.Fatalf("transition before any sighting = %d, want 0", got)
	}
	if p.isPresent() {
		t.Fatal("present before any sighting")
	}

	// First sighting confirms immediately.
	p.sighting(at(1 * time.Second))
	if got := p.transition(at(1 * time.Second)); got != 1 {
		t.Fatalf("transition on first sighting = %d, want +1", got)
	}

	// Re-sighting within the window: stays present, no new edge.
	p.sighting(at(20 * time.Second))
	if got := p.transition(at(20 * time.Second)); got != 0 {
		t.Fatalf("transition while still present = %d, want 0", got)
	}

	// Just inside the absence window from the last sighting (20s + 30s = 50s):
	// at 49s still present.
	if got := p.transition(at(49 * time.Second)); got != 0 {
		t.Fatalf("transition just inside absence window = %d, want 0", got)
	}
	// Past the window → exactly one -1.
	if got := p.transition(at(51 * time.Second)); got != -1 {
		t.Fatalf("transition past absence window = %d, want -1", got)
	}
	if p.isPresent() {
		t.Fatal("still present after absence timeout")
	}
	// Idempotent: no second -1.
	if got := p.transition(at(60 * time.Second)); got != 0 {
		t.Fatalf("second transition after absence = %d, want 0", got)
	}
}

// TestPresenceDebounceNoFlip verifies the confirm window swallows a transient: a
// single sighting that does not persist confirmAfter never emits an appear edge.
func TestPresenceDebounceConfirmWindow(t *testing.T) {
	p := newPresence(10*time.Second, 30*time.Second)

	// One sighting, then evaluate immediately - run hasn't spanned confirmAfter.
	p.sighting(at(0))
	if got := p.transition(at(0)); got != 0 {
		t.Fatalf("transition before confirm window = %d, want 0", got)
	}
	if p.isPresent() {
		t.Fatal("confirmed before confirm window elapsed")
	}

	// A gap longer than absenceAfter restarts the run, so a later lone sighting
	// still must wait the full confirm window - a transient blip never confirms.
	p.sighting(at(45 * time.Second))
	if got := p.transition(at(45 * time.Second)); got != 0 {
		t.Fatalf("transition on restarted run = %d, want 0", got)
	}

	// Sustained sightings spanning the confirm window → confirm.
	p.sighting(at(50 * time.Second))
	if got := p.transition(at(56 * time.Second)); got != 1 {
		t.Fatalf("transition after sustained run = %d, want +1", got)
	}
}
