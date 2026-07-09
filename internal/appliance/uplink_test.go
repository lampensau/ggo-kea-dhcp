package appliance

import "testing"

// TestUplinkAuditDebounce verifies the uplink audit collapses repeated identical
// outcomes to one transition: the first observation always counts, repeats of the same
// state do not, and a flip does. This is what keeps a persistently failing (or re-saved
// working) uplink from spamming UPLINK_DOWN/UPLINK_UP on every reconcile.
func TestUplinkAuditDebounce(t *testing.T) {
	var u uplinkAudit

	// First down: counts (unknown -> down).
	if !u.observe(false) {
		t.Fatal("first observation should report a transition")
	}
	// Staying down: suppressed.
	if u.observe(false) {
		t.Fatal("repeated down should not report a transition")
	}
	// Recovery: down -> up counts.
	if !u.observe(true) {
		t.Fatal("down -> up should report a transition")
	}
	// Staying up (e.g. Settings re-saved unchanged): suppressed.
	if u.observe(true) {
		t.Fatal("repeated up should not report a transition")
	}
	// Going down again counts.
	if !u.observe(false) {
		t.Fatal("up -> down should report a transition")
	}
}
