package netmon

import (
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

// returnsWithin runs fn in a goroutine and fails if it does not return within d, so a
// hanging Stop (the exact failure the SO_RCVTIMEO fix prevents on a silent link) fails
// the test instead of wedging the whole suite.
func returnsWithin(t *testing.T, what string, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v (deadlock/hang)", what, d)
	}
}

// TestMonitorManager_StopPromptWithSilentSniffer is the netmon analogue of the
// arpscan anti-hang proof: a FakeSniffer that is never Pushed (a silent link, no
// frames) must still Stop promptly. At the Go level serveOnce selects over quit /
// Frames() / tick, so closing quit unblocks it even though no frame ever arrives -
// the same liveness the real socket gets from SO_RCVTIMEO + fd close.
func TestMonitorManager_StopPromptWithSilentSniffer(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer() // never Pushed -> Frames() never delivers
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return fs, nil }
	mm, _ := fastManager(openFn, clk)

	mm.Start([]Spec{{Iface: "eth0"}})

	// Wait until the monitor has actually produced a snapshot (it is live and ticking
	// even with zero frames) before timing the Stop.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(mm.SnapshotAll()) == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if len(mm.SnapshotAll()) == 0 {
		t.Fatal("silent sniffer never produced a snapshot - monitor did not start ticking")
	}

	returnsWithin(t, "MonitorManager.Stop with a silent sniffer", 2*time.Second, mm.Stop)
}

// TestMonitorManager_StopIdempotent proves Stop is safe before any Start and when
// called twice - the reconciler calls Start (which calls Stop first) on every ACTIVE
// entry, and the ACTIVE-exit paths (apply/switch/onboarding) call Stop directly.
func TestMonitorManager_StopIdempotent(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return fs, nil }
	mm, _ := fastManager(openFn, clk)

	returnsWithin(t, "Stop before any Start", time.Second, mm.Stop)

	mm.Start([]Spec{{Iface: "eth0"}})
	returnsWithin(t, "first Stop", 2*time.Second, mm.Stop)
	returnsWithin(t, "second Stop (idempotent)", time.Second, mm.Stop)

	if got := len(mm.SnapshotAll()); got != 0 {
		t.Fatalf("Stop must clear all snapshots; got %d remaining", got)
	}
	if got := mm.Running(); len(got) != 0 {
		t.Fatalf("Stop must leave no running monitors; got %v", got)
	}
}

// TestNopSniffer_CloseUnblocksRange guards the TrunkProbe deadlock fix. TrunkProbe.loop
// consumes frames with a bare `for range sn.Frames()` (no quit select, unlike the
// Monitor), so it returns only when Close() actually closes the channel. The original
// nopSniffer.Close() was a no-op, so that range - and TrunkProbe.Stop's wg.Wait - hung
// forever whenever openCapture fell back to a nopSniffer (no CAP_NET_RAW, or eth0
// absent), wedging the onboarding->active apply. Close must also be safe to call twice
// (an explicit Stop racing serveOnce's deferred close).
func TestNopSniffer_CloseUnblocksRange(t *testing.T) {
	sn := newNopSniffer()
	returnsWithin(t, "range over nopSniffer.Frames() after Close", 2*time.Second, func() {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_ = sn.Close()
			_ = sn.Close() // double close must not panic (sync.Once)
		}()
		for range sn.Frames() { // the TrunkProbe.loop shape
		}
	})
}

// TestMonitor_NopSnifferStopsCleanly drives the dev-mode no-op sniffer (no socket /
// no CAP_NET_RAW): the interface is marked Available=false but the monitor still
// ticks and, crucially, Stop returns promptly even though nopSniffer.Frames() never
// delivers - quit ends serveOnce, and Close now also closes the channel.
func TestMonitor_NopSnifferStopsCleanly(t *testing.T) {
	clk := newFakeClock(base)
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return newNopSniffer(), nil }
	mm, _ := fastManager(openFn, clk)

	mm.Start([]Spec{{Iface: "eth0"}})

	// The nop sniffer surfaces as an Available=false snapshot.
	deadline := time.Now().Add(2 * time.Second)
	sawUnavailable := false
	for time.Now().Before(deadline) {
		for _, s := range mm.SnapshotAll() {
			if s.Iface == "eth0" && !s.Available {
				sawUnavailable = true
			}
		}
		if sawUnavailable {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !sawUnavailable {
		t.Fatal("nop sniffer should yield an Available=false snapshot for eth0")
	}

	returnsWithin(t, "MonitorManager.Stop with a nop sniffer", 2*time.Second, mm.Stop)
}

// TestMonitor_StopWhileDrainingFrames proves Stop is prompt even while the sniffer is
// actively delivering frames (the read path is busy, not idle): a background pusher
// keeps feeding queries right up until Stop. quit wins the serveOnce select, so Stop
// is still bounded.
func TestMonitor_StopWhileDrainingFrames(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return fs, nil }
	mm, _ := fastManager(openFn, clk)

	mm.Start([]Spec{{Iface: "eth0"}})

	stopPush := make(chan struct{})
	pushDone := make(chan struct{})
	go func() {
		defer close(pushDone)
		for {
			select {
			case <-stopPush:
				return
			default:
				fs.Push(igmpQuery([4]byte{10, 0, 0, 1}, 2))
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// Let the monitor consume a few frames so the read path is genuinely active.
	waitForDetector(t, mm, "eth0", "igmp", func(d DetectorSnapshot) bool { return d.Severity == SevOK })

	returnsWithin(t, "MonitorManager.Stop while frames are draining", 2*time.Second, mm.Stop)
	close(stopPush)
	<-pushDone
}
