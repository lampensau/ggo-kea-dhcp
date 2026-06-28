package netmon

import (
	"strings"
	"testing"
	"time"
)

func TestSACN_ConflictSamePriority(t *testing.T) {
	d := newSACNDetector("eth0", 30*time.Second)

	// Two different sources on universe 1 at the SAME priority → conflict.
	d.Consume(sacnData(1, cid16(0xa1), 100), at(1*time.Second))
	d.Consume(sacnData(1, cid16(0xb2), 100), at(1*time.Second))
	ev := d.Tick(at(1 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one conflict warn, got %v", ev)
	}
	// The audit detail names the shared priority and the contending CIDs.
	if got := ev[0].After; !strings.Contains(got, "priority 100") ||
		!strings.Contains(got, "a1a1a1a1") || !strings.Contains(got, "b2b2b2b2") {
		t.Fatalf("conflict detail lacks priority/CIDs: %q", got)
	}
	if s := d.Snapshot(); s.Severity != SevWarn {
		t.Fatalf("snapshot during conflict = %+v", s)
	}
}

func TestSACN_DuplicateCID(t *testing.T) {
	d := newSACNDetector("eth0", 30*time.Second)
	// Same CID, two different source names = two devices misconfigured alike.
	cid := cid16(0xa1)
	d.Consume(sacnDataEx(3, cid, 100, "Console-A", 0), at(1*time.Second))
	d.Consume(sacnDataEx(3, cid, 100, "Console-B", 0), at(1*time.Second))
	ev := d.Tick(at(1 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn || ev[0].Action != "sACN duplicate CID" {
		t.Fatalf("expected one duplicate-CID warn, got %v", ev)
	}
	// Debounced: no repeat event on the next tick.
	if ev := d.Tick(at(2 * time.Second)); ev != nil {
		t.Fatalf("duplicate-CID should emit once, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevWarn {
		t.Fatalf("snapshot during duplicate CID = %+v", s)
	}
}

func TestSACN_StreamTerminatedClearsConflict(t *testing.T) {
	d := newSACNDetector("eth0", 30*time.Second)
	d.Consume(sacnData(4, cid16(0xa1), 100), at(1*time.Second))
	d.Consume(sacnData(4, cid16(0xb2), 100), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 1 {
		t.Fatalf("expected conflict, got %v", ev)
	}
	// One source cleanly terminates → conflict clears immediately (no 30s wait).
	d.Consume(sacnDataEx(4, cid16(0xb2), 100, "", optStreamTerminated), at(2*time.Second))
	ev := d.Tick(at(2 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected conflict-cleared info, got %v", ev)
	}
}

func TestSACN_NonDataVectorIgnored(t *testing.T) {
	d := newSACNDetector("eth0", 30*time.Second)
	f := sacnData(5, cid16(0xa1), 100)
	// Corrupt the framing vector to a non-data value (e.g. a sync packet).
	_, off, _, _ := etherInfo(f.Data)
	_, _, _, l4, _ := ipv4Info(f.Data, off)
	_, _, payload, _ := udpPorts(f.Data, l4)
	f.Data[payload+43] = 0x08 // framing vector -> 0x00000008
	d.Consume(f, at(1*time.Second))
	d.Tick(at(1 * time.Second))
	if s := d.Snapshot(); s.Text != "No sACN traffic seen" {
		t.Fatalf("non-data vector should be ignored, snapshot = %+v", s)
	}
}

func TestSACN_DifferentPriorityIsInfo(t *testing.T) {
	d := newSACNDetector("eth0", 30*time.Second)
	// Two sources at DIFFERENT priorities = intended backup → info, not warn.
	d.Consume(sacnData(2, cid16(0xa1), 100), at(1*time.Second))
	d.Consume(sacnData(2, cid16(0xb2), 80), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("priority backup should not emit a conflict event: %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevInfo {
		t.Fatalf("snapshot = %+v, want info", s)
	}
}
