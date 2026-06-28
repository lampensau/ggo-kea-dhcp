package netmon

import (
	"testing"
	"time"
)

func TestDuplicateIP_FlagsDecline(t *testing.T) {
	d := newDuplicateIPDetector("eth0", 300*time.Second)

	d.Consume(declineFrame([4]byte{10, 0, 0, 42}), at(1*time.Second))
	ev := d.Tick(at(1 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one warn conflict event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevWarn || s.Fields["address"] != "10.0.0.42" {
		t.Fatalf("snapshot = %+v", s)
	}

	// Cleared after the absence window.
	if ev := d.Tick(at(400 * time.Second)); len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one clear event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot after clear = %+v", s)
	}
}

func TestDuplicateIP_IgnoresNonDecline(t *testing.T) {
	d := newDuplicateIPDetector("eth0", 300*time.Second)
	d.Consume(dhcpFrame(67, [4]byte{10, 0, 0, 1}, 5), at(1*time.Second)) // ACK, not DECLINE
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("ACK produced conflict events: %v", ev)
	}
}
