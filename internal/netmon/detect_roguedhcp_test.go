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
