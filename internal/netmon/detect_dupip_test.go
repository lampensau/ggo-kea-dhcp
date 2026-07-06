package netmon

import (
	"testing"
	"time"
)

func TestDuplicateIP_FlagsDecline(t *testing.T) {
	d := newDuplicateIPDetector("eth0", 0, 300*time.Second)

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
	d := newDuplicateIPDetector("eth0", 0, 300*time.Second)
	d.Consume(dhcpFrame(67, [4]byte{10, 0, 0, 1}, 5), at(1*time.Second)) // ACK, not DECLINE
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("ACK produced conflict events: %v", ev)
	}
}

// The untagged eth0 monitor sees in-band-tagged DECLINEs leaking off the trunk; the
// servedVID gate must drop a foreign VLAN's DECLINE so it isn't mis-attributed to
// eth0, while the served VLAN's own DECLINE is still counted.
func TestDuplicateIP_ForeignVLANIgnored(t *testing.T) {
	d := newDuplicateIPDetector("eth0", 0, 300*time.Second) // serves untagged (vid 0)

	d.Consume(declineFrameVLAN(20, [4]byte{10, 20, 0, 5}), at(1*time.Second))
	if len(d.conflicts) != 0 {
		t.Fatalf("a VLAN-20 DECLINE was counted on the untagged monitor: %d conflicts", len(d.conflicts))
	}

	d.Consume(declineFrame([4]byte{10, 0, 0, 5}), at(2*time.Second))
	if len(d.conflicts) != 1 {
		t.Fatalf("the served (untagged) DECLINE was not counted: %d conflicts", len(d.conflicts))
	}
}

// A monitor serving a tagged scope counts only its own VLAN's DECLINEs.
func TestDuplicateIP_ServedVLANCounted(t *testing.T) {
	d := newDuplicateIPDetector("eth0.20", 20, 300*time.Second)
	d.Consume(declineFrameVLAN(20, [4]byte{10, 20, 0, 5}), at(1*time.Second))
	d.Consume(declineFrame([4]byte{10, 0, 0, 5}), at(2*time.Second)) // untagged, foreign to this scope
	if len(d.conflicts) != 1 {
		t.Fatalf("served VLAN 20 should count only its own DECLINE: %d conflicts", len(d.conflicts))
	}
}
