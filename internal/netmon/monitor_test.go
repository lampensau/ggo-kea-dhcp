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

func TestMonitor_PromiscuousSingleOwner(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	openFn := func(string, bool, []bpf.RawInstruction) (Sniffer, error) { return fs, nil }
	mm, _ := fastManager(openFn, clk)
	defer mm.Stop()

	// MulticastSniff on → the duty-cycler may open a promiscuous window at L0.
	mm.Start([]Spec{{Iface: "eth0", MulticastSniff: true}})

	// Let serveOnce initialize its duty baseline (lastToggle = clock now) before
	// advancing the clock, otherwise the advance could land before the baseline is
	// taken and the window would never appear due.
	time.Sleep(30 * time.Millisecond)
	// Advance past the duty-off interval so the window opens at L0 → promiscuous on.
	clk.Advance(defaultDutyOff + time.Second)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		log := fs.PromiscLog()
		if len(log) > 0 && log[len(log)-1] {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if log := fs.PromiscLog(); len(log) == 0 || !log[len(log)-1] {
		t.Fatalf("promiscuous never enabled at L0 in a duty window: %v", log)
	}

	// Now drive sustained overflow → governor sheds to >=L1 → promiscuous forced
	// off even though the duty window is still open.
	fs.SetStats(100, 100)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		log := fs.PromiscLog()
		if len(log) > 0 && !log[len(log)-1] {
			return // last toggle was OFF - governor reclaimed the ceiling
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("governor did not force promiscuous off after shedding: %v", fs.PromiscLog())
}

// countingDetector records how many frames it consumed (H4 fan-out gating test).
type countingDetector struct{ consumed int }

func (c *countingDetector) Consume(Frame, time.Time) { c.consumed++ }
func (c *countingDetector) Tick(time.Time) []Event   { return nil }
func (c *countingDetector) Snapshot() DetectorSnapshot {
	return DetectorSnapshot{Kind: "counting", Severity: SevOK}
}

// TestHandleFrame_LevelGating proves L2+ stops the per-frame parse cost while L0/L1
// still fan out - i.e. L2 is a real rung, not a no-op of L1.
func TestHandleFrame_LevelGating(t *testing.T) {
	cd := &countingDetector{}
	m := &Monitor{
		spec:      Spec{Iface: "eth0"},
		clock:     func() time.Time { return base },
		gov:       newGovernor(defaultGovConfig()),
		detectors: []*detectorSlot{{d: cd, kind: "counting"}},
	}

	// L0: consumed.
	m.handleFrame(igmpQuery([4]byte{10, 0, 0, 1}, 2))
	// L1 (drop promiscuous): still parses narrow-BPF frames.
	m.gov.level = LevelNoPromisc
	m.handleFrame(igmpQuery([4]byte{10, 0, 0, 1}, 2))
	if cd.consumed != 2 {
		t.Fatalf("L0/L1 consumed %d frames, want 2", cd.consumed)
	}
	// L2 (counters-only): frame dropped unparsed.
	m.gov.level = LevelCountersOnly
	m.handleFrame(igmpQuery([4]byte{10, 0, 0, 1}, 2))
	// L3 (paused): also dropped.
	m.gov.level = LevelPaused
	m.handleFrame(igmpQuery([4]byte{10, 0, 0, 1}, 2))
	if cd.consumed != 2 {
		t.Fatalf("L2/L3 consumed extra frames (%d total) - should drop unparsed", cd.consumed)
	}
}

// TestMonitor_L2FreezesPresenceNoFalseLost guards N1: at LevelCountersOnly the
// frame-fed presence detectors are frozen and run on the blind-time-eliding
// frame-clock, so holding L2 well past PTP's 15s absence window - and climbing
// back to L1 - never produces a false "PTP grandmaster lost".
func TestMonitor_L2FreezesPresenceNoFalseLost(t *testing.T) {
	clk := newFakeClock(base)
	fs := NewFakeSniffer()
	rs := &recordingSink{}
	ptp := newPTPDetector("eth0", 15*time.Second)
	storm := newStormDetector("eth0", 1000, nil)
	m := &Monitor{
		spec:  Spec{Iface: "eth0"},
		gov:   newGovernor(testGovConfig()),
		store: NewSnapshotStore(),
		sink:  rs.sink,
		clock: clk.Now,
		detectors: []*detectorSlot{
			{d: ptp, kind: "ptp", counterFed: false},
			{d: storm, kind: "storm", counterFed: true},
		},
	}

	// Establish a present grandmaster at L0.
	m.handleFrame(ptpAnnounce(0, 0x1, 128, 128, false))
	m.onTick(fs, true)
	if got := snapshotKind(m, "ptp").Severity; got != SevOK {
		t.Fatalf("PTP not present after announce: %v", got)
	}

	// Drive to L2 with sustained overflow (stepDownAfter=2 → 4 breach ticks),
	// advancing the clock only a little so PTP stays present during the descent.
	fs.SetStats(10, 10)
	for range 4 {
		clk.Advance(time.Second)
		m.onTick(fs, true)
	}
	if m.gov.currentLevel() < LevelCountersOnly {
		t.Fatalf("did not reach L2: %v", m.gov.currentLevel())
	}

	// Hold L2 far past the 15s absence window. Frozen → no lost event, and the
	// card reports "unknown" rather than a stale or false status.
	clk.Advance(60 * time.Second)
	m.onTick(fs, true)
	if got := rs.byAction("PTP grandmaster lost"); got != 0 {
		t.Fatalf("false 'PTP grandmaster lost' fired while frozen at L2 (%d)", got)
	}
	if s := snapshotKind(m, "ptp"); s.Text != "status unknown - reduced monitoring" {
		t.Fatalf("frozen PTP snapshot = %q, want 'status unknown'", s.Text)
	}

	// Resume: calm signals climb back to L0/L1; a present GM keeps announcing.
	fs.SetStats(0, 0)
	for range 12 {
		clk.Advance(time.Second)
		m.handleFrame(ptpAnnounce(0, 0x1, 128, 128, false))
		m.onTick(fs, true)
	}
	// The blind interval was elided, so no false lost ever fired across the whole
	// L2-hold-and-recover sequence.
	if got := rs.byAction("PTP grandmaster lost"); got != 0 {
		t.Fatalf("false 'PTP grandmaster lost' fired across L2/resume (%d)", got)
	}
	if m.gov.currentLevel() != LevelFull {
		t.Fatalf("did not recover to L0 after sustained calm: %v", m.gov.currentLevel())
	}
}

// snapshotKind returns the current snapshot for one detector kind on m.
func snapshotKind(m *Monitor, kind string) DetectorSnapshot {
	for _, s := range m.detectors {
		if s.kind == kind {
			return m.snapshotOne(s, framesDropped(m.gov.currentLevel()))
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

func TestNewDetectors_SACNGatedOnMulticastSniff(t *testing.T) {
	// sACN is multicast-only (UDP 5568): without promiscuous capture the detector
	// is blind, so it must be attached only when the scope opted into multicast
	// sniffing - otherwise the card shows a false "no sACN traffic" on a comms-only
	// deployment. Count is the cheap invariant: sniff adds exactly the sACN detector.
	off := newDetectors(Spec{Iface: "eth0"}, Thresholds{}, nil, nil)
	on := newDetectors(Spec{Iface: "eth0", MulticastSniff: true}, Thresholds{}, nil, nil)
	if len(on) != len(off)+1 {
		t.Fatalf("MulticastSniff should add exactly the sACN detector: off=%d on=%d", len(off), len(on))
	}
}
