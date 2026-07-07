package netmon

import (
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	monitorTick        = 2 * time.Second
	defaultFaultBudget = 5
	baseBackoff        = 500 * time.Millisecond
	maxBackoff         = 30 * time.Second
	monitorNice        = 10 // lowered priority so the kernel favors Kea + the UI
)

// OpenFunc opens a capture for one interface. openCapture is the production
// implementation; tests inject one returning a FakeSniffer (the
// NewMonitorManagerWithSniffer seam).
type OpenFunc func(iface string, promisc bool, filter []bpf.RawInstruction) (Sniffer, error)

// Spec describes one interface to monitor. The reconciler builds these from the
// served scopes (eth0 / eth0.<vid>) - never wlan0.
type Spec struct {
	Iface string
	// Greengo marks an interface served by a Green-GO-preset scope: it attaches the
	// Green-GO census + config detectors and the UDP-5810 BPF clause. Off on
	// non-Green-GO scopes so they neither run those detectors nor capture 5810.
	Greengo      bool
	InterfaceIPs [][4]byte // our IPs on this iface (static-in-pool infra exclusion)
	// InterfaceMAC is the box's own L2 address on this iface's NIC; the rogue-DHCP
	// detector suppresses our own OFFER/ACK by matching it (a source-MAC fact, not
	// the forgeable option-54 server-id). InterfaceMACSet is false when it could not
	// be read (dev sandbox / iface down), in which case no self-suppression is done.
	InterfaceMAC    [6]byte
	InterfaceMACSet bool
	Pools           []PoolRange
	ConfiguredVIDs  []int
	Leases          LeaseSnapshotFunc
	// LeaseLifetime is the active profile's lease lifetime in seconds. The
	// static-in-pool detector sizes its lease-history grace to ~T1 (half of it) so a
	// client that just lost a lease isn't flagged as static before it can re-DHCP.
	LeaseLifetime int
	// WatchVLANs attaches the VLAN-reality detector to this monitor. It is set only
	// on the raw eth0 monitor (the untagged scope's), never on an eth0.<vid>
	// sub-interface monitor - the kernel delivers tag-stripped frames there, so the
	// detector would run blind. (Hardware-verify R1: full tag visibility on raw
	// eth0 also needs RX-VLAN offload disabled or PACKET_AUXDATA tag recovery.)
	WatchVLANs bool
	// RawTrunkOnly marks a synthesized raw-eth0 monitor for a pure-trunk profile
	// (no untagged scope): it runs ONLY the VLAN-reality detector, so the other
	// detectors don't misfire on a monitor that has no served scope of its own
	// (e.g. static-in-pool with no configured pool, or a scope-less rogue watch).
	RawTrunkOnly bool
}

// Thresholds are the detector tunables read from app_state (with code defaults).
type Thresholds struct {
	IGMPAbsence time.Duration
	StormPPS    int
}

// detectorSlot wraps a Detector with a degraded flag: a detector that panics in
// Consume/Tick/Snapshot is isolated and skipped thereafter, without taking down
// the interface's monitor.
type detectorSlot struct {
	d    Detector
	kind string // cached at construction so a degraded snapshot keeps its Kind
	// counterFed marks a detector whose Tick reads out-of-band counters (sysfs)
	// rather than the frame stream - only the storm detector. Counter-fed detectors
	// tick on the real clock; frame-fed detectors tick on the frame-clock, which
	// pauses while frames are being dropped so their absence timers don't run down
	// against frames they never received (see onTick).
	counterFed bool
	degraded   bool
}

// safeKind reads a detector's Kind once at construction (its Snapshot returns a
// static Kind even with no data), under recover for total safety.
func safeKind(d Detector) (k string) {
	k = "detector"
	defer func() { _ = recover() }()
	if got := d.Snapshot().Kind; got != "" {
		k = got
	}
	return k
}

// newDetectors builds the per-interface detector set. A RawTrunkOnly spec (the
// synthesized raw-eth0 monitor for a pure-trunk profile) runs ONLY VLAN-reality.
// Otherwise the standard set runs, and VLAN-reality is attached only when
// WatchVLANs is set (the raw eth0 monitor) - never on an eth0.<vid> monitor,
// where tags are stripped and it would run blind.
func newDetectors(spec Spec, th Thresholds, rx rxCounterFunc, linkUp linkStateFunc) []Detector {
	if spec.RawTrunkOnly {
		return []Detector{newVLANDetector(spec.Iface, spec.ConfiguredVIDs, linkUp)}
	}
	infra := make([]uint32, 0, len(spec.InterfaceIPs))
	for _, ip := range spec.InterfaceIPs {
		infra = append(infra, ip4ToU32(ip))
	}
	// The served VID for this monitor (0 = the untagged eth0 scope, N = eth0.N).
	// Detectors that judge per-VLAN facts use it to separate what belongs to THIS
	// served VLAN from what leaks in from an unserved/foreign VLAN on the trunk
	// (in-band tag on the untagged socket).
	vid := vidFromIface(spec.Iface)
	dets := []Detector{
		newIGMPDetector(spec.Iface, th.IGMPAbsence),
		newLLDPDetector(spec.Iface, linkUp),
		newRogueDHCPDetector(spec.Iface, spec.InterfaceMAC, spec.InterfaceMACSet, vid, 0),
		newDuplicateIPDetector(spec.Iface, vid, 0),
		newPTPDetector(spec.Iface, 0),
		newStormDetector(spec.Iface, th.StormPPS, rx),
		newIdleDetector(spec.Iface, rx),
		newStaticInPoolDetector(spec.Iface, spec.Pools, infra, spec.Leases, 0, spec.LeaseLifetime),
	}
	// The Green-GO detectors (passive census + config decode) attach only on a
	// Green-GO-preset interface - the only place Green-GO gear and the 5810 bus live.
	if spec.Greengo {
		dets = append(dets,
			newGreengoDetector(spec.Iface, spec.Leases, 0, vid),
			newGreengoHDetector(spec.Iface, 0, vid),
		)
	}
	if spec.WatchVLANs {
		dets = append(dets, newVLANDetector(spec.Iface, spec.ConfiguredVIDs, linkUp))
	}
	return dets
}

// vidFromIface returns the served 802.1Q VID for a monitor's interface name: 0 for a
// plain "eth0" (the untagged scope), or N for an "eth0.N" sub-interface.
func vidFromIface(iface string) int {
	if i := strings.LastIndexByte(iface, '.'); i >= 0 {
		if v, err := strconv.Atoi(iface[i+1:]); err == nil {
			return v
		}
	}
	return 0
}

// Monitor runs one interface: a single WaitGroup-tracked goroutine that binds an
// OS thread + nices it ONCE, then loops over a recover-wrapped serveOnce. Restart
// is the inner loop (never a re-spawn), shutdown is the quit select.
type Monitor struct {
	spec      Spec
	openFn    OpenFunc
	filter    []bpf.RawInstruction
	detectors []*detectorSlot
	store     *SnapshotStore
	sink      EventSink
	clock     func() time.Time

	tickInterval time.Duration
	baseBackoff  time.Duration
	faultBudget  int

	quit chan struct{}
	wg   sync.WaitGroup

	mu      sync.Mutex
	cur     Sniffer
	stopped bool

	joiner *multicastJoiner

	// Frame-clock: a clock for the frame-fed detectors that PAUSES for any tick in
	// which the capture is dropping frames (either overflow counter rose: an
	// AF_PACKET socket-buffer drop or a frame-channel drop-on-full). Their
	// absence/debounce timers run on clock()-frameClockOffset, so a blind interval
	// is elided rather than counted as the subject going absent - preventing false
	// "lost" alarms under a control-frame storm and on the recovery afterward. The
	// counter-fed storm detector always uses the real clock. Touched only on the
	// monitor goroutine.
	frameClockOffset time.Duration
	lastTickNow      time.Time
	prevBlind        bool
	haveTick         bool
}

// framesFreezer is implemented by hybrid detectors (storm) that have a frame-fed
// half needing to freeze when frames are dropped, even though the detector is
// counter-fed overall and keeps ticking through a blind stretch.
type framesFreezer interface{ setFramesDropped(bool) }

// frameNow returns the frame-fed detector clock (real clock minus accumulated
// blind time).
func (m *Monitor) frameNow() time.Time { return m.clock().Add(-m.frameClockOffset) }

// resetTickBaseline clears the frame-clock's per-capture tick baseline (see
// serveOnce). Touched only on the monitor goroutine, like the fields it clears.
//
// TRADEOFF (deliberate, not a pure win): not crediting the fault+backoff gap means
// frameNow jumps FORWARD by that gap (up to maxBackoff) on the first post-restart
// tick, instead of staying frozen. A genuinely-absent device is then reported lost
// promptly (the fix). The flip-side: a still-PRESENT short-window frame-fed detector
// - PTP grandmaster most of all (absence threshold in seconds) - can fire a brief
// false "lost" on that first tick, because its last sighting predates the blackout
// and now reads gap-stale against the jumped clock. It self-heals within one announce
// interval once the device re-announces. We accept that for this warn-only monitor
// (netmon never mutates Kea): a self-healing blip right after an already-abnormal
// fault is better than reporting a real loss up to maxBackoff late, and "we were
// blind for the gap, reconfirm before trusting presence" is the honest posture.
func (m *Monitor) resetTickBaseline() {
	m.prevBlind = false
	m.haveTick = false
}

func newMonitor(spec Spec, openFn OpenFunc, detectors []Detector, store *SnapshotStore, sink EventSink, clock func() time.Time, tick, backoff time.Duration, budget int) *Monitor {
	slots := make([]*detectorSlot, len(detectors))
	for i, d := range detectors {
		// sysfs-counter-fed detectors read out-of-band counters, not the frame stream,
		// so they tick on the real clock while frame-fed detectors run on the
		// blind-time-eliding frame-clock.
		var counterFed bool
		switch d.(type) {
		case *stormDetector, *idleDetector:
			counterFed = true
		}
		slots[i] = &detectorSlot{d: d, kind: safeKind(d), counterFed: counterFed}
	}
	filter, err := buildFilter(spec.Greengo)
	if err != nil {
		// A bad filter is a programming bug; fall back to no kernel filter
		// (correctness preserved - detectors still ignore uninteresting frames).
		log.Printf("[netmon] %s: BPF assemble failed (%v) - capturing unfiltered", spec.Iface, err)
		filter = nil
	}
	return &Monitor{
		spec: spec, openFn: openFn, filter: filter, detectors: slots,
		store: store, sink: sink, clock: clock,
		tickInterval: tick, baseBackoff: backoff, faultBudget: budget,
		quit: make(chan struct{}),
	}
}

func (m *Monitor) start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		// Bind to this OS thread ONCE and nice it. The binding (and thus the nice,
		// a property of this task) persists across a same-goroutine recover and
		// prevents the runtime from migrating the goroutine - so we never re-apply
		// it per iteration (LockOSThread is ref-counted; re-locking would grow lock
		// depth with no matching Unlock). No Unlock: on return the runtime discards
		// this locked, nice'd thread rather than returning it dirty to the pool.
		runtime.LockOSThread()
		applyNice(m.spec.Iface)

		backoff := m.baseBackoff
		for {
			select {
			case <-m.quit:
				return
			default:
			}
			panicked, err := m.serveOnce()
			switch {
			case panicked:
				m.faultBudget--
				log.Printf("[netmon serve-fault iface=%s] framework panic (budget left %d)", m.spec.Iface, m.faultBudget)
			case err == nil:
				return // clean shutdown / clean exit - NOT a fault
			default:
				m.faultBudget--
				log.Printf("[netmon serve-fault iface=%s] %v (budget left %d)", m.spec.Iface, err, m.faultBudget)
			}
			if m.faultBudget <= 0 {
				m.markPermanentlyDegraded()
				return
			}
			// Interruptible backoff: a Stop() (e.g. a CONFIGURING re-IP) during the
			// sleep must not be stalled for the full interval.
			select {
			case <-m.quit:
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}

// Stop closes quit, closes the current sniffer to unblock the read, and waits for
// the goroutine. Honest even when a profile switch races a panic: restart is an
// inner loop (no escaped goroutine), and the top-of-loop quit check prevents a
// restart after Stop.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		m.wg.Wait()
		return
	}
	m.stopped = true
	cur := m.cur
	m.cur = nil
	m.mu.Unlock()

	close(m.quit)
	if cur != nil {
		_ = cur.Close()
	}
	m.wg.Wait()
}

// setCur publishes the active sniffer so Stop can close it. Returns false if Stop
// already ran (the caller must close the sniffer and bail) - closes the race
// where a sniffer opened after Stop would otherwise leak.
func (m *Monitor) setCur(s Sniffer) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return false
	}
	m.cur = s
	return true
}

func (m *Monitor) closeCur() {
	m.mu.Lock()
	s := m.cur
	m.cur = nil
	m.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
}

// serveOnce opens a capture and serves it until quit (clean: nil) or a fault
// (panic → panicked=true; unexpected close / open error → err != nil). The
// recover here is the SERVE layer (a framework bug in the fan-out/tick machinery);
// per-detector Consume/Tick recovers are a separate layer with distinguishable
// logs, so nobody chases a detector bug when the fault is in the loop.
func (m *Monitor) serveOnce() (panicked bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			log.Printf("[netmon serve-panic iface=%s] %v", m.spec.Iface, r)
		}
	}()

	sn, oerr := m.openFn(m.spec.Iface, false, m.filter)
	if oerr != nil {
		return false, oerr
	}
	if !m.setCur(sn) { // stopped during open
		_ = sn.Close()
		return false, nil
	}
	defer m.closeCur()

	available := !isNop(sn)
	cc, _ := sn.(capControl)
	m.joiner = nil
	// A restarted capture has no prior tick of its OWN to diff against. Clear the
	// frame-clock's per-capture tick baseline so the first onTick doesn't bill the
	// fault-plus-backoff gap (up to maxBackoff) as blind time and rewind frameNow,
	// which would delay frame-fed "lost" firing for one window right after a fault.
	// frameClockOffset (real accumulated blind time) is deliberately preserved.
	m.resetTickBaseline()
	// Join the cheap, fixed known groups (PTP + mDNS) whenever we have a real
	// capture socket. These are benign receiver joins (no promiscuous, no querier,
	// low rate), so PTP-over-UDP (319/320 -> 224.0.1.129-132) is observable for
	// Stride / AES67 (PTPv2) clocks - PTP must always be legible (see detect_ptp).
	if cc != nil && cc.socketFD() >= 0 {
		m.joiner = newMulticastJoiner(cc.socketFD(), cc.ifIndex())
		if jerr := m.joiner.joinKnown(); jerr != nil {
			log.Printf("[netmon] %s join known multicast groups: %v", m.spec.Iface, jerr)
		}
	}

	frames := sn.Frames()
	tick := time.NewTicker(m.tickInterval)
	defer tick.Stop()
	for {
		select {
		case <-m.quit:
			return false, nil
		case f, ok := <-frames:
			if !ok {
				select {
				case <-m.quit:
					return false, nil // clean: Stop closed the fd
				default:
					return false, errSnifferClosed // fault
				}
			}
			m.handleFrame(f)
		case <-tick.C:
			m.onTick(cc, available)
		}
	}
}

// handleFrame fans one frame out to every live detector, then enforces the
// no-retention invariant by poisoning the buffer (debug builds only). Frame-fed
// detectors run on the frame-clock so a blind interval (frames dropped under load)
// is elided from their absence timers (see frameNow).
func (m *Monitor) handleFrame(f Frame) {
	frameNow := m.frameNow()
	real := m.clock()
	for _, s := range m.detectors {
		if s.degraded {
			continue
		}
		now := frameNow
		if s.counterFed {
			now = real
		}
		m.consumeOne(s, f, now)
	}
	poison(f.Data) // after the FULL fan-out - a retained slice reads poison next access
}

func (m *Monitor) consumeOne(s *detectorSlot, f Frame, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			s.degraded = true
			log.Printf("[netmon detector-fault iface=%s detector=%T] Consume panic (detector degraded): %v", m.spec.Iface, s.d, r)
		}
	}()
	s.d.Consume(f, now)
}

func (m *Monitor) onTick(cc capControl, available bool) {
	now := m.clock()

	// Advance the frame-clock offset by the interval just elapsed if the capture
	// was dropping frames during it, so the frame-fed detectors never count blind
	// time as absence: without this, a control-frame storm that overflows the
	// capture makes short-window detectors like PTP emit false "lost" both during
	// the storm and on the climb back.
	if m.haveTick && m.prevBlind {
		m.frameClockOffset += now.Sub(m.lastTickNow)
	}

	// Either overflow counter rising means the capture fell behind and dropped
	// frames this tick - an AF_PACKET socket-buffer drop (tpDrops) or a
	// frame-channel drop-on-full (chanDrops). That is the blindness signal the
	// frame-clock keys on. Wire pps is deliberately NOT consulted: a busy-but-healthy
	// show LAN runs enormous pps with zero drops (the in-kernel BPF sheds the flood),
	// so a pps signal would freeze the frame-clock on exactly the healthy networks
	// this monitor targets.
	var tpDrops, chanDrops uint32
	if cc != nil {
		tpDrops, chanDrops = cc.stats()
	}
	blind := tpDrops > 0 || chanDrops > 0

	frameNow := m.frameNow()
	for _, s := range m.detectors {
		if s.degraded {
			continue
		}
		// The hybrid storm detector freezes its frame-fed half while blind (its
		// counter-fed half keeps counting off sysfs).
		if fz, ok := s.d.(framesFreezer); ok {
			fz.setFramesDropped(blind)
		}
		tn := frameNow
		if s.counterFed {
			tn = now
		}
		for _, e := range m.tickOne(s, tn) {
			if m.sink != nil {
				m.sink(e)
			}
		}
	}
	m.publishSnapshot(available)

	m.prevBlind = blind
	m.lastTickNow = now
	m.haveTick = true
}

func (m *Monitor) tickOne(s *detectorSlot, now time.Time) (events []Event) {
	defer func() {
		if r := recover(); r != nil {
			s.degraded = true
			events = nil
			log.Printf("[netmon detector-fault iface=%s detector=%T] Tick panic (detector degraded): %v", m.spec.Iface, s.d, r)
		}
	}()
	return s.d.Tick(now)
}

func (m *Monitor) publishSnapshot(available bool) {
	snap := Snapshot{Iface: m.spec.Iface, Available: available}
	if !available {
		snap.Note = "monitoring idle - no capture socket (dev mode or no privilege)"
	}
	for _, s := range m.detectors {
		snap.Detectors = append(snap.Detectors, m.snapshotOne(s))
		// The unleased-pool-host list rides in the same snapshot; skipped when the
		// detector is degraded.
		if sp, ok := s.d.(*staticInPoolDetector); ok && !s.degraded {
			snap.UnleasedPoolHosts = sp.unleasedPoolHosts()
		}
	}
	m.store.Update(m.spec.Iface, snap)
}

func (m *Monitor) snapshotOne(s *detectorSlot) (ds DetectorSnapshot) {
	if s.degraded {
		return DetectorSnapshot{Kind: s.kind, Severity: SevInfo, Text: "detector unavailable (internal fault)"}
	}
	defer func() {
		if r := recover(); r != nil {
			s.degraded = true
			ds = DetectorSnapshot{Kind: s.kind, Severity: SevInfo, Text: "detector unavailable (internal fault)"}
		}
	}()
	return s.d.Snapshot()
}

func (m *Monitor) markPermanentlyDegraded() {
	m.store.Update(m.spec.Iface, Snapshot{
		Iface:     m.spec.Iface,
		Available: false,
		Note:      "monitoring unavailable - repeated fault",
	})
	log.Printf("[netmon iface=%s] permanently degraded after repeated serve-level faults", m.spec.Iface)
}

// applyNice lowers the calling (thread-locked) goroutine's scheduling priority.
func applyNice(iface string) {
	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, monitorNice); err != nil {
		log.Printf("[netmon] %s set nice: %v (continuing at default priority)", iface, err)
	}
}

// MonitorManager owns the per-interface monitors with a Start (Stop-then-start,
// idempotent, best-effort) and Stop lifecycle. It reads netmon_enabled /
// thresholds via an injected GetState so netmon imports neither web nor db.
type MonitorManager struct {
	mu       sync.Mutex
	monitors map[string]*Monitor
	openFn   OpenFunc
	store    *SnapshotStore
	sink     EventSink
	getState func(string) (string, error)
	clock    func() time.Time

	// test knobs (defaults set in newManager; overridden in white-box tests)
	tickInterval time.Duration
	baseBackoff  time.Duration
	faultBudget  int
	detectorsFor func(Spec, Thresholds, rxCounterFunc, linkStateFunc) []Detector
}

// NewMonitorManager builds the production manager (real AF_PACKET capture).
func NewMonitorManager(getState func(string) (string, error), sink EventSink) *MonitorManager {
	return newManager(openCapture, getState, sink)
}

// NewMonitorManagerWithSniffer is the test seam: it injects a custom OpenFunc
// (e.g. one returning a FakeSniffer).
func NewMonitorManagerWithSniffer(openFn OpenFunc, getState func(string) (string, error), sink EventSink) *MonitorManager {
	return newManager(openFn, getState, sink)
}

func newManager(openFn OpenFunc, getState func(string) (string, error), sink EventSink) *MonitorManager {
	return &MonitorManager{
		monitors:     make(map[string]*Monitor),
		openFn:       openFn,
		store:        NewSnapshotStore(),
		sink:         sink,
		getState:     getState,
		clock:        time.Now,
		tickInterval: monitorTick,
		baseBackoff:  baseBackoff,
		faultBudget:  defaultFaultBudget,
		detectorsFor: newDetectors,
	}
}

// SnapshotAll exposes the store for the web layer (buildNetHealthView).
func (mm *MonitorManager) SnapshotAll() []Snapshot { return mm.store.SnapshotAll() }

// Running returns the interfaces currently monitored (sorted), for the
// reconciler's ACTIVE-only state-gate tests.
func (mm *MonitorManager) Running() []string {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	out := make([]string, 0, len(mm.monitors))
	for iface := range mm.monitors {
		out = append(out, iface)
	}
	sort.Strings(out)
	return out
}

// Start (re)starts monitors for specs. It is best-effort by contract: it launches
// goroutines and returns immediately, is panic-safe, and NEVER returns an error
// that could abort reconcileActive (the core apply path). Stops existing monitors
// first (idempotent). Specs for wlan0 / non-served interfaces are hard-rejected.
func (mm *MonitorManager) Start(specs []Spec) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[netmon] Start panic (ignored, monitoring is subordinate): %v", r)
		}
	}()
	mm.Stop()

	if !mm.enabled() {
		log.Printf("[netmon] disabled via netmon_enabled - not starting monitors")
		return
	}
	th := mm.loadThresholds()

	mm.mu.Lock()
	defer mm.mu.Unlock()
	for _, spec := range specs {
		if !validIface(spec.Iface) {
			log.Printf("[netmon] refusing to monitor %q (only served eth0/eth0.<vid> - never the uplink)", spec.Iface)
			continue
		}
		rx := sysfsRxReader(spec.Iface)
		link := sysfsLinkReader(spec.Iface)
		dets := mm.detectorsFor(spec, th, rx, link)
		mon := newMonitor(spec, mm.openFn, dets, mm.store, mm.sink, mm.clock, mm.tickInterval, mm.baseBackoff, mm.faultBudget)
		mon.start()
		mm.monitors[spec.Iface] = mon
	}
}

// Stop tears down all monitors and clears their snapshots. Idempotent.
func (mm *MonitorManager) Stop() {
	mm.mu.Lock()
	mons := mm.monitors
	mm.monitors = make(map[string]*Monitor)
	mm.mu.Unlock()
	for iface, mon := range mons {
		mon.Stop()
		mm.store.Remove(iface)
	}
}

func (mm *MonitorManager) enabled() bool {
	if mm.getState == nil {
		return true
	}
	v, _ := mm.getState("netmon_enabled")
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "off", "no":
		return false
	default:
		return true // default on (missing key)
	}
}

func (mm *MonitorManager) loadThresholds() Thresholds {
	th := Thresholds{IGMPAbsence: defaultIGMPAbsence, StormPPS: defaultStormPPS}
	if mm.getState == nil {
		return th
	}
	if v, _ := mm.getState("netmon_igmp_timeout"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			th.IGMPAbsence = time.Duration(n) * time.Second
		}
	}
	if v, _ := mm.getState("netmon_storm_pps"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			th.StormPPS = n
		}
	}
	return th
}

// linkStateFunc reports whether the interface carrier is up (a cable is present and
// the link is established). Detectors that key a latched fact off the physical link
// (lldp "you are here", vlan-reality) consult it to invalidate ONLY on a real link
// drop, never on frame silence.
type linkStateFunc func() bool

// sysfsLinkReader reads /sys/class/net/<iface>/carrier ("1" = up). Fail-open: a read
// error or absent file (dev sandbox / no interface) returns true, so a latched fact
// is never cleared on uncertainty - only on a confirmed carrier-down. A VLAN
// sub-interface (eth0.<vid>) has its own carrier file that follows the parent.
func sysfsLinkReader(iface string) linkStateFunc {
	path := "/sys/class/net/" + iface + "/carrier"
	return func() bool {
		b, err := os.ReadFile(path)
		if err != nil {
			return true // fail-open: unknown link state is treated as up
		}
		return strings.TrimSpace(string(b)) == "1"
	}
}

// sysfsRxReader reads the interface's cumulative rx-packets counter; ok is false
// when the file is absent (dev sandbox / no interface).
func sysfsRxReader(iface string) rxCounterFunc {
	path := "/sys/class/net/" + iface + "/statistics/rx_packets"
	return func() (uint64, bool) {
		b, err := os.ReadFile(path)
		if err != nil {
			return 0, false
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
}

// validIface enforces the wlan0-exclusion invariant defensively: only the served
// eth0 / eth0.<vid> interfaces may be monitored. Monitoring the uplink would
// flag the upstream router's DHCP as rogue and make IGMP/PTP absence meaningless.
func validIface(iface string) bool {
	if iface == "eth0" {
		return true
	}
	if strings.HasPrefix(iface, "eth0.") {
		_, err := strconv.Atoi(iface[len("eth0."):])
		return err == nil
	}
	return false
}
