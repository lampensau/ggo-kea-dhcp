package netmon

import (
	"testing"
	"time"
)

func TestRogueDHCP_FlagsForeignServerNotSelf(t *testing.T) {
	self := [4]byte{10, 0, 0, 1}
	d := newRogueDHCPDetector("eth0", [][4]byte{self}, 120*time.Second)

	// Our own server's OFFER is suppressed.
	d.Consume(dhcpFrame(67, self, 2), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("self OFFER flagged as rogue: %v", ev)
	}

	// A foreign server's OFFER is a high-severity rogue.
	d.Consume(dhcpFrame(67, [4]byte{10, 0, 0, 250}, 2), at(2*time.Second))
	ev := d.Tick(at(2 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevError {
		t.Fatalf("expected one error event, got %v", ev)
	}
	s := d.Snapshot()
	if s.Severity != SevError || s.Fields["server"] != "10.0.0.250" {
		t.Fatalf("snapshot = %+v", s)
	}
	if s.Fields["mac"] == "" {
		t.Fatal("rogue server MAC not captured")
	}

	// Still present on the next tick (no duplicate event).
	d.Consume(dhcpFrame(67, [4]byte{10, 0, 0, 250}, 5), at(60*time.Second))
	if ev := d.Tick(at(60 * time.Second)); ev != nil {
		t.Fatalf("duplicate event while rogue still present: %v", ev)
	}

	// Gone past the absence window → cleared (info), snapshot back to ok.
	if ev := d.Tick(at(200 * time.Second)); len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one gone event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot after clear = %+v", s)
	}
}

// TestRogueDHCP_SustainedGate proves the sustained flag distinguishes a single (forgeable)
// OFFER - which confirms presence for the Network Health row but must NOT be reported as
// sustained - from a rogue seen repeatedly across the sustain window. The web layer gates
// the loud one-click stand-down banner on this flag.
func TestRogueDHCP_SustainedGate(t *testing.T) {
	d := newRogueDHCPDetector("eth0", [][4]byte{{10, 0, 0, 1}}, 120*time.Second)
	rogue := [4]byte{10, 0, 0, 250}

	// One OFFER: presence is confirmed (the detector row is immediate) but NOT sustained.
	d.Consume(dhcpFrame(67, rogue, 2), at(1*time.Second))
	d.Tick(at(1 * time.Second))
	s := d.Snapshot()
	if s.Severity != SevError {
		t.Fatalf("a single OFFER should still flag the detector row: %+v", s)
	}
	if s.Fields["sustained"] != "0" {
		t.Fatalf("a single OFFER must not be reported as sustained: %+v", s)
	}

	// A second OFFER past the sustain window: the run now spans it → sustained.
	d.Consume(dhcpFrame(67, rogue, 5), at(35*time.Second))
	d.Tick(at(35 * time.Second))
	if s := d.Snapshot(); s.Fields["sustained"] != "1" {
		t.Fatalf("a rogue seen across the sustain window should be sustained: %+v", s)
	}
}
