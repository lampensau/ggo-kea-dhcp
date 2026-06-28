package netmon

import (
	"testing"
	"time"
)

func TestStorm_VolumeFromCounterDeltas(t *testing.T) {
	var counter uint64
	d := newStormDetector("eth0", 1000, func() (uint64, bool) { return counter, true })

	// First tick establishes the baseline (no pps yet).
	d.Tick(at(0))
	// +3000 packets over 1s = 3000 pps (> threshold) for two consecutive ticks.
	counter += 3000
	d.Tick(at(1 * time.Second))
	counter += 3000
	ev := d.Tick(at(2 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one storm warn after sustained high pps, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevWarn {
		t.Fatalf("snapshot during storm = %+v", s)
	}

	// Quiet tick (no counter movement) → storm clears.
	ev = d.Tick(at(3 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one clear event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot after clear = %+v", s)
	}
}

// TestStorm_NoLatchOnReadFailure guards M5: a storm must clear (not latch) when
// the rx counter read starts failing.
func TestStorm_NoLatchOnReadFailure(t *testing.T) {
	var counter uint64
	ok := true
	d := newStormDetector("eth0", 1000, func() (uint64, bool) {
		if !ok {
			return 0, false
		}
		return counter, true
	})

	// Drive a storm.
	d.Tick(at(0))
	counter += 3000
	d.Tick(at(1 * time.Second))
	counter += 3000
	if ev := d.Tick(at(2 * time.Second)); len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected storm warn, got %v", ev)
	}

	// The counter read now fails - curPPS must go quiet and the storm must clear,
	// not latch on its last high value.
	ok = false
	ev := d.Tick(at(3 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("storm did not clear on read failure (latched): %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot after read failure = %+v, want ok", s)
	}
}

// TestStorm_STPChurnFrozenWhileBlind guards the N1-cousin: while frames are
// dropped (L2), the frame-fed STP-churn half must freeze rather than false-clear
// because BPDUs stopped arriving.
func TestStorm_STPChurnFrozenWhileBlind(t *testing.T) {
	d := newStormDetector("eth0", 100000, nil)
	for range stpChurnThreshold {
		d.Consume(bpduFrame(true), at(0))
	}
	if ev := d.Tick(at(0)); len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected STP churn warn, got %v", ev)
	}

	// Frames now dropped (monitor at L2). Past the 30s window, the churn half is
	// frozen → no false "stabilized".
	d.setFramesDropped(true)
	if ev := d.Tick(at(60 * time.Second)); len(ev) != 0 {
		t.Fatalf("STP churn false-cleared while blind: %v", ev)
	}

	// On resume, churn evaluation runs again and clears honestly (window elapsed,
	// no new BPDUs being a real signal now that we're looking).
	d.setFramesDropped(false)
	if ev := d.Tick(at(120 * time.Second)); len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected stabilized on resume, got %v", ev)
	}
}

func TestStorm_STPChurn(t *testing.T) {
	d := newStormDetector("eth0", 100000, nil) // no rx reader → volume path silent

	for i := 0; i < stpChurnThreshold; i++ {
		d.Consume(bpduFrame(true), at(time.Duration(i)*time.Second))
	}
	ev := d.Tick(at(time.Duration(stpChurnThreshold) * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one STP churn warn, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevWarn {
		t.Fatalf("snapshot during churn = %+v", s)
	}

	// Churn ages out of the window → stabilized.
	if ev := d.Tick(at(60 * time.Second)); len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one stabilized event, got %v", ev)
	}
}
