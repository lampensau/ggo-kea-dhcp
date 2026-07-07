package netmon

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

// recordingSink is a thread-safe EventSink for asserting audit emission.
type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingSink) sink(e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

// all returns a copy of every recorded event (locked), for diagnosing an
// unexpected over-count in a failure message.
func (r *recordingSink) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

func (r *recordingSink) byAction(action string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Action == action {
			n++
		}
	}
	return n
}

// fastManager builds a manager with a controllable clock, tiny tick/backoff, and a
// recording sink, wired to the given OpenFunc.
func fastManager(openFn OpenFunc, clk *fakeClock) (*MonitorManager, *recordingSink) {
	rs := &recordingSink{}
	mm := NewMonitorManagerWithSniffer(openFn, nil, rs.sink)
	mm.clock = clk.Now
	mm.tickInterval = 2 * time.Millisecond
	mm.baseBackoff = time.Millisecond
	mm.faultBudget = 3
	return mm, rs
}

// waitForDetector polls the store until the named detector on iface satisfies
// pred, or fails after a generous deadline.
func waitForDetector(t *testing.T, mm *MonitorManager, iface, kind string, pred func(DetectorSnapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range mm.SnapshotAll() {
			if s.Iface != iface {
				continue
			}
			for _, d := range s.Detectors {
				if d.Kind == kind && pred(d) {
					return
				}
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s/%s predicate", iface, kind)
}

func TestMonitorManager_AuditOncePerTransition(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return fs, nil }
	mm, rs := fastManager(openFn, clk)
	defer mm.Stop()

	mm.Start([]Spec{{Iface: "eth0"}})

	// Querier appears: push queries and let the tick confirm presence.
	for i := 0; i < 3; i++ {
		fs.Push(igmpQuery([4]byte{10, 0, 0, 1}, 2))
	}
	waitForDetector(t, mm, "eth0", "igmp", func(d DetectorSnapshot) bool { return d.Severity == SevOK })

	// Querier lost: advance the clock past the absence window.
	clk.Advance(10 * time.Minute)
	waitForDetector(t, mm, "eth0", "igmp", func(d DetectorSnapshot) bool { return d.Severity == SevWarn })

	// Assert on the IGMP querier's OWN transition actions, not the aggregate
	// severity: a 10-minute jump on a full eth0 monitor can make ANOTHER detector
	// emit a SevWarn ("No traffic on interface", etc.), and whether that extra warn
	// lands before this read is a scheduler race - the source of the historical
	// flaky "warn audit rows = 2". byAction isolates the transition this test is
	// actually about: one present (appear), one lost (lost), never per-tick.
	if got := rs.byAction("IGMP querier present"); got != 1 {
		t.Errorf("'IGMP querier present' audited %d times, want 1 (one per transition, not per tick); events=%+v", got, rs.all())
	}
	if got := rs.byAction("IGMP querier lost"); got != 1 {
		t.Errorf("'IGMP querier lost' audited %d times, want 1; events=%+v", got, rs.all())
	}
}

func TestMonitorManager_StartBestEffortSwallowsOpenError(t *testing.T) {
	clk := newFakeClock(base)
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) {
		return nil, errors.New("boom: no permission")
	}
	mm, _ := fastManager(openFn, clk)
	defer mm.Stop()

	// Start must not panic and must return promptly even though every open fails.
	done := make(chan struct{})
	go func() { mm.Start([]Spec{{Iface: "eth0"}}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return promptly (best-effort contract violated)")
	}

	// Budget exhausts → honest terminal snapshot, process intact.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range mm.SnapshotAll() {
			if s.Iface == "eth0" && !s.Available && s.Note == "monitoring unavailable - repeated fault" {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("did not reach the budget-exhaustion terminal state")
}

// panickingDetector panics in Consume to prove serve-level isolation.
type panickingDetector struct{ iface string }

func (p *panickingDetector) Consume(Frame, time.Time) { panic("boom in Consume") }
func (p *panickingDetector) Tick(time.Time) []Event   { return nil }
func (p *panickingDetector) Snapshot() DetectorSnapshot {
	return DetectorSnapshot{Kind: "panicky", Severity: SevOK, Subject: p.iface}
}

func TestMonitorManager_DetectorPanicIsolation(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return fs, nil }
	mm, _ := fastManager(openFn, clk)
	mm.detectorsFor = func(spec Spec, th Thresholds, rx rxCounterFunc, linkUp linkStateFunc) []Detector {
		return []Detector{
			&panickingDetector{iface: spec.Iface},
			newIGMPDetector(spec.Iface, th.IGMPAbsence), // a healthy detector beside it
		}
	}
	defer mm.Stop()
	mm.Start([]Spec{{Iface: "eth0"}})

	// Feed a frame: the panicking detector blows up in Consume but is isolated.
	for i := 0; i < 3; i++ {
		fs.Push(igmpQuery([4]byte{10, 0, 0, 1}, 2))
	}
	// The healthy IGMP detector still confirms the querier - the monitor survived
	// and other detectors keep emitting snapshots.
	waitForDetector(t, mm, "eth0", "igmp", func(d DetectorSnapshot) bool { return d.Severity == SevOK })

	// The bad detector is marked degraded (its snapshot shows the placeholder).
	waitForDetector(t, mm, "eth0", "panicky", func(d DetectorSnapshot) bool {
		return d.Text == "detector unavailable (internal fault)"
	})
}

// closedSniffer's Frames channel is already closed → serveOnce sees an unexpected
// close (a fault) on every open, exercising the restart loop.
type closedSniffer struct{ ch chan Frame }

func newClosedSniffer() *closedSniffer {
	c := make(chan Frame)
	close(c)
	return &closedSniffer{ch: c}
}
func (s *closedSniffer) Frames() <-chan Frame { return s.ch }
func (s *closedSniffer) Close() error         { return nil }

func TestMonitorManager_StopRacesFaultNoLeak(t *testing.T) {
	clk := newFakeClock(base)
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return newClosedSniffer(), nil }
	mm, _ := fastManager(openFn, clk)
	mm.faultBudget = 1 << 20 // keep restarting so Stop must interrupt, not budget

	mm.Start([]Spec{{Iface: "eth0"}})
	time.Sleep(10 * time.Millisecond) // let it churn through several fault/restart cycles

	done := make(chan struct{})
	go func() { mm.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop hung - goroutine leaked or wg.Wait blocked by the restart loop")
	}
}

func TestMonitorManager_PromptStopDuringBackoff(t *testing.T) {
	clk := newFakeClock(base)
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) {
		return nil, errors.New("always fails → forces backoff")
	}
	mm, _ := fastManager(openFn, clk)
	mm.baseBackoff = 5 * time.Second // a long backoff Stop must interrupt
	mm.faultBudget = 1 << 20

	mm.Start([]Spec{{Iface: "eth0"}})
	time.Sleep(10 * time.Millisecond) // ensure the goroutine is parked in the backoff select

	start := time.Now()
	mm.Stop()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Stop took %v - backoff sleep was not interruptible", elapsed)
	}
}

// TestMonitor_FrameClockFreezesPresenceNoFalseLost guards the frame-clock: when the
// capture is dropping frames (an overflow counter rises), the frame-fed presence
// detectors run on the blind-time-eliding frame-clock, so holding a blind period
// well past PTP's 15s absence window - and recovering afterward - never produces a
// false "PTP grandmaster lost". This is the re-anchored N1 invariant: the trigger
// is the drop counters, not a governor level.
func TestMonitor_FrameClockFreezesPresenceNoFalseLost(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	rs := &recordingSink{}
	ptp := newPTPDetector("eth0", 15*time.Second)
	m := &Monitor{
		spec:      Spec{Iface: "eth0"},
		store:     NewSnapshotStore(),
		sink:      rs.sink,
		clock:     clk.Now,
		detectors: []*detectorSlot{{d: ptp, kind: "ptp", counterFed: false}},
	}

	// Establish a present grandmaster with no drops.
	m.handleFrame(ptpAnnounce(0, 0x1, 128, 128, false))
	m.onTick(fs, true)
	if got := snapshotKind(m, "ptp").Severity; got != SevOK {
		t.Fatalf("PTP not present after announce: %v", got)
	}

	// Begin dropping frames. One small blind tick arms prevBlind so the subsequent
	// long interval is absorbed into the frame-clock offset.
	fs.SetStats(10, 10)
	clk.Advance(time.Second)
	m.onTick(fs, true)

	// Hold the blind period far past the 15s absence window: the interval is elided,
	// so PTP never goes "lost" and the card still reports it present.
	clk.Advance(60 * time.Second)
	m.onTick(fs, true)
	if got := rs.byAction("PTP grandmaster lost"); got != 0 {
		t.Fatalf("false 'PTP grandmaster lost' fired while blind (%d)", got)
	}
	if got := snapshotKind(m, "ptp").Severity; got != SevOK {
		t.Fatalf("PTP snapshot = %v while blind, want still present", got)
	}

	// Recover: drops stop, the GM keeps announcing, and no false lost ever fired
	// across the whole blind-hold-and-recover sequence.
	fs.SetStats(0, 0)
	for range 12 {
		clk.Advance(time.Second)
		m.handleFrame(ptpAnnounce(0, 0x1, 128, 128, false))
		m.onTick(fs, true)
	}
	if got := rs.byAction("PTP grandmaster lost"); got != 0 {
		t.Fatalf("false 'PTP grandmaster lost' fired across blind/resume (%d)", got)
	}
}

// snapshotKind returns the current snapshot for one detector kind on m.
func snapshotKind(m *Monitor, kind string) DetectorSnapshot {
	for _, s := range m.detectors {
		if s.kind == kind {
			return m.snapshotOne(s)
		}
	}
	return DetectorSnapshot{}
}

func TestValidIface_NeverWlan0(t *testing.T) {
	cases := map[string]bool{
		"eth0": true, "eth0.100": true, "eth0.4094": true,
		"wlan0": false, "eth1": false, "eth0.": false, "eth0.x": false, "": false,
	}
	for iface, want := range cases {
		if got := validIface(iface); got != want {
			t.Errorf("validIface(%q) = %v, want %v", iface, got, want)
		}
	}
}

func TestMonitorManager_RejectsWlan0Spec(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return fs, nil }
	mm, _ := fastManager(openFn, clk)
	defer mm.Stop()

	mm.Start([]Spec{{Iface: "eth0"}, {Iface: "wlan0"}})
	// wlan0 must never produce a monitor / snapshot.
	time.Sleep(20 * time.Millisecond)
	for _, s := range mm.SnapshotAll() {
		if s.Iface == "wlan0" {
			t.Fatal("wlan0 was monitored - the uplink-exclusion guard failed")
		}
	}
}

// TestMonitor_ResetTickBaselineNoBlindGapAfterRestart is the #120 regression guard:
// after a capture faults while blind, the fault-plus-backoff gap (no ticks, up to
// maxBackoff) must NOT be billed as blind time on the first tick of the restarted
// capture. serveOnce clears the per-capture tick baseline, so frameClockOffset does
// not jump by the dead interval and frameNow is not spuriously rewound.
func TestMonitor_ResetTickBaselineNoBlindGapAfterRestart(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	m := &Monitor{
		spec:      Spec{Iface: "eth0"},
		store:     NewSnapshotStore(),
		clock:     clk.Now,
		detectors: []*detectorSlot{},
	}

	// Healthy tick, then a blind tick: arms prevBlind/haveTick with no offset yet.
	m.onTick(fs, true)
	fs.SetStats(10, 10)
	clk.Advance(time.Second)
	m.onTick(fs, true)
	if m.frameClockOffset != 0 {
		t.Fatalf("offset after arming blind tick = %v, want 0", m.frameClockOffset)
	}

	// The capture faults and the restart loop backs off - no ticks for the whole gap.
	clk.Advance(maxBackoff)

	// serveOnce clears the baseline for the restarted (healthy) capture; the first
	// tick must not accumulate the dead gap.
	m.resetTickBaseline()
	fs.SetStats(0, 0)
	m.onTick(fs, true)
	if m.frameClockOffset != 0 {
		t.Fatalf("first tick after restart billed the dead gap as blind time: offset = %v, want 0", m.frameClockOffset)
	}
}

// TestMonitor_RestartReportsGenuineLossPromptly is the behavioral half of #120: it
// drives a real PTP detector across present -> blind -> fault -> restart and asserts
// the INTENDED lost-timing, not just the frameClockOffset scalar. After a blind fault
// the frame-clock baseline is cleared, so frameNow advances across the gap and a GM
// that is genuinely gone is reported lost on the first post-restart tick - the fix's
// whole point (the old code credited the gap and stalled this for a window). A GM that
// is still present recovers on its next announce (the documented self-healing blip).
func TestMonitor_RestartReportsGenuineLossPromptly(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	rs := &recordingSink{}
	ptp := newPTPDetector("eth0", 15*time.Second)
	m := &Monitor{
		spec:      Spec{Iface: "eth0"},
		store:     NewSnapshotStore(),
		sink:      rs.sink,
		clock:     clk.Now,
		detectors: []*detectorSlot{{d: ptp, kind: "ptp", counterFed: false}},
	}

	// Present GM, then a blind tick right before the capture faults.
	m.handleFrame(ptpAnnounce(0, 0x1, 128, 128, false))
	m.onTick(fs, true)
	fs.SetStats(10, 10)
	clk.Advance(time.Second)
	m.onTick(fs, true)

	// Fault + backoff: no ticks for the whole gap, then the restart clears the baseline.
	clk.Advance(30 * time.Second)
	m.resetTickBaseline()
	fs.SetStats(0, 0)

	// The GM is genuinely gone (no re-announce). The first post-restart tick must
	// report it lost promptly rather than crediting the 30s gap and stalling.
	m.onTick(fs, true)
	if got := rs.byAction("PTP grandmaster lost"); got != 1 {
		t.Fatalf("genuine loss not reported promptly after restart: got %d 'lost' events, want 1", got)
	}

	// A device that comes back announces again and recovers - the blip self-heals.
	clk.Advance(time.Second)
	m.handleFrame(ptpAnnounce(0, 0x1, 128, 128, false))
	m.onTick(fs, true)
	if got := rs.byAction("PTP grandmaster seen"); got < 1 {
		t.Fatalf("GM did not recover after re-announce: got %d 'seen' events, want >=1", got)
	}
}
