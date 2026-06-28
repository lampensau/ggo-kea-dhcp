package netmon

import (
	"testing"
	"time"
)

// drainTicks runs Tick at now and returns the events (nil-safe helper).
func igmpAt(d *igmpDetector, now time.Time) []Event { return d.Tick(now) }

func TestIGMPDetector_PresenceThenAbsence(t *testing.T) {
	d := newIGMPDetector("eth0", 300*time.Second)

	// Before any query: informational, no events.
	if ev := igmpAt(d, at(0)); ev != nil {
		t.Fatalf("events before any query: %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevInfo {
		t.Fatalf("severity before query = %q, want info", s.Severity)
	}

	// A general query from .1 confirms a querier and emits one ok transition.
	d.Consume(igmpQuery([4]byte{10, 0, 0, 1}, 2), at(1*time.Second))
	ev := igmpAt(d, at(1*time.Second))
	if len(ev) != 1 || ev[0].Severity != SevOK {
		t.Fatalf("expected one ok appear event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK || s.Fields["querier"] != "10.0.0.1" || s.Fields["version"] != "v2" {
		t.Fatalf("snapshot after query = %+v", s)
	}

	// Re-query within the window: stays ok, no new event.
	d.Consume(igmpQuery([4]byte{10, 0, 0, 1}, 2), at(120*time.Second))
	if ev := igmpAt(d, at(120*time.Second)); ev != nil {
		t.Fatalf("unexpected event while querier still present: %v", ev)
	}

	// No queries past the absence window → exactly one warn transition.
	ev = igmpAt(d, at(500*time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one warn lost event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevWarn {
		t.Fatalf("snapshot after loss = %+v", s)
	}
	// Idempotent: no repeat warn on the next tick.
	if ev := igmpAt(d, at(560*time.Second)); ev != nil {
		t.Fatalf("repeat event after loss: %v", ev)
	}
}

// TestIGMPDetector_VersionWithEthernetPadding guards M1: a real v2 query rides in
// a frame padded to the 60-byte minimum; the version must read from the IP
// total-length, not the padded frame length (which would mis-sniff v3).
func TestIGMPDetector_VersionWithEthernetPadding(t *testing.T) {
	d := newIGMPDetector("eth0", 300*time.Second)
	f := igmpQuery([4]byte{10, 0, 0, 1}, 2) // 8-byte IGMPv2 message
	if len(f.Data) < 60 {                   // pad to the Ethernet minimum, as a NIC would
		padded := make([]byte, 60)
		copy(padded, f.Data)
		f.Data = padded
	}
	d.Consume(f, at(1*time.Second))
	d.Tick(at(1 * time.Second))
	if s := d.Snapshot(); s.Fields["version"] != "v2" {
		t.Fatalf("padded v2 query read as %q, want v2", s.Fields["version"])
	}
}

func TestIGMPDetector_IgnoresNonQuery(t *testing.T) {
	d := newIGMPDetector("eth0", 300*time.Second)
	// A DHCP-ish broadcast frame must not register as a querier.
	d.Consume(dhcpFrame(67, [4]byte{10, 0, 0, 9}, 2), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("non-IGMP frame produced events: %v", ev)
	}
	if d.pres.isPresent() {
		t.Fatal("querier confirmed from a non-IGMP frame")
	}
}
