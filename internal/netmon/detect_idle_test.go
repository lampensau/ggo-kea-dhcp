package netmon

import (
	"testing"
	"time"
)

// fakeRx returns a counter func reading the value pointed to by p, so a test can
// advance "received packets" between ticks.
func fakeRx(p *uint64, ok bool) rxCounterFunc {
	return func() (uint64, bool) { return *p, ok }
}

func TestIdleDetector(t *testing.T) {
	var pkts uint64 = 100
	d := newIdleDetector("eth0.20", fakeRx(&pkts, true))
	base := time.Unix(0, 0)

	// Within the grace window, no warning even with zero traffic.
	if ev := d.Tick(base); len(ev) != 0 {
		t.Fatalf("first tick should be silent, got %v", ev)
	}
	if ev := d.Tick(base.Add(idleAbsence - time.Second)); len(ev) != 0 {
		t.Fatalf("pre-window tick should not warn, got %v", ev)
	}

	// Past the window with no counter change -> warn once.
	ev := d.Tick(base.Add(idleAbsence + time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one warn event, got %v", ev)
	}
	if d.Snapshot().Severity != SevWarn {
		t.Fatalf("snapshot should be warn while idle")
	}
	// Latched: no repeat warning on the next idle tick.
	if ev := d.Tick(base.Add(idleAbsence + 2*time.Second)); len(ev) != 0 {
		t.Fatalf("warning should latch, got %v", ev)
	}

	// Traffic resumes -> clears.
	pkts = 150
	ev = d.Tick(base.Add(idleAbsence + 3*time.Second))
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one clear event, got %v", ev)
	}
	if d.Snapshot().Severity != SevOK {
		t.Fatalf("snapshot should be ok after traffic resumes")
	}
}

// An unavailable counter (dev sandbox) must never warn.
func TestIdleDetectorNoCounter(t *testing.T) {
	var pkts uint64
	d := newIdleDetector("eth0", fakeRx(&pkts, false))
	base := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		if ev := d.Tick(base.Add(time.Duration(i) * idleAbsence)); len(ev) != 0 {
			t.Fatalf("no warning without a counter, got %v", ev)
		}
	}
	if d.Snapshot().Severity != SevOK {
		t.Fatalf("snapshot should stay ok without a counter")
	}
}
