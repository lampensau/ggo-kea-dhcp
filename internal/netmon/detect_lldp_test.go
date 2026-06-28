package netmon

import (
	"testing"
	"time"
)

func TestLLDPDetector_LatchesAndNeighborFields(t *testing.T) {
	d := newLLDPDetector("eth0", nil) // nil linkUp => always up

	d.Consume(lldpFrame("core-sw-1", "Gi1/0/24", 100), at(1*time.Second))
	ev := d.Tick(at(1 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one info 'seen' event, got %v", ev)
	}
	s := d.Snapshot()
	if s.Severity != SevOK {
		t.Fatalf("severity = %q, want ok", s.Severity)
	}
	if s.Fields["switch"] != "core-sw-1" || s.Fields["port"] != "Gi1/0/24" || s.Fields["native_vlan"] != "100" {
		t.Fatalf("fields = %+v", s.Fields)
	}

	// Frame silence must NOT flap the chip: many ticks later, no events, still OK.
	// (The old aging model dropped the neighbor here - the flap this fix removes.)
	for i := 2; i < 12; i++ {
		if ev := d.Tick(at(time.Duration(i) * time.Minute)); len(ev) != 0 {
			t.Fatalf("tick @%dm emitted %v - a latched neighbor must not flap on silence", i, ev)
		}
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("severity after long silence = %q, want ok (latched)", s.Severity)
	}
}

// TestLLDPDetector_DoesNotBlankKnownFields proves a later frame that lacks the System
// Name (a switch interleaves LLDP/CDP frames that don't all carry every TLV) does NOT
// blank a previously-learned neighbor - the bug that flapped the "you are here" label
// between the rich info and "unknown switch" every ~90s.
func TestLLDPDetector_DoesNotBlankKnownFields(t *testing.T) {
	d := newLLDPDetector("eth0", nil)
	d.Consume(lldpFrame("core-sw-1", "Gi1/0/24", 100), at(1*time.Second))
	d.Tick(at(1 * time.Second))
	if s := d.Snapshot(); s.Fields["switch"] != "core-sw-1" {
		t.Fatalf("did not learn switch name: %+v", s.Fields)
	}
	// A frame with an empty System Name TLV must NOT blank the learned name.
	d.Consume(lldpFrame("", "Gi1/0/24", 100), at(2*time.Second))
	d.Tick(at(2 * time.Second))
	s := d.Snapshot()
	if s.Fields["switch"] != "core-sw-1" {
		t.Fatalf("empty-name frame blanked the switch name: %+v", s.Fields)
	}
	if s.Severity != SevOK {
		t.Fatalf("severity should stay OK (latched), got %q", s.Severity)
	}
}

func TestLLDPDetector_ClearsOnLinkDownAndReLatches(t *testing.T) {
	up := true
	d := newLLDPDetector("eth0", func() bool { return up })

	d.Consume(lldpFrame("core-sw-1", "Gi1/0/24", 100), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 1 {
		t.Fatalf("seen: want 1 event, got %v", ev)
	}

	// Link drops: exactly one "lost" event, and the snapshot leaves OK.
	up = false
	ev := d.Tick(at(2 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevInfo || ev[0].After != "link down" {
		t.Fatalf("expected one link-down lost event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevInfo {
		t.Fatalf("severity after link down = %q, want info", s.Severity)
	}

	// Link back up + a new advertisement (different port) re-latches to the new neighbor.
	up = true
	d.Consume(lldpFrame("core-sw-2", "Gi2/0/1", 200), at(3*time.Second))
	if ev := d.Tick(at(3 * time.Second)); len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("re-latch: want one 'seen' event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK || s.Fields["switch"] != "core-sw-2" || s.Fields["port"] != "Gi2/0/1" {
		t.Fatalf("re-latched snapshot = %+v", s)
	}
}
