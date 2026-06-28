package web

import (
	"log"
	"strings"
	"sync"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// metricsSampleInterval is the always-on sampling cadence. It is deliberately
// slower than the live ticker (liveTickInterval) and independent of it: the
// ticker only runs while an operator is watching, but the sampler must keep the
// ring buffers warm so a dashboard opened cold shows trend history immediately.
const metricsSampleInterval = 12 * time.Second

// metricsCap is the ring length. At metricsSampleInterval that is ~18 min of
// history - enough to fill a sparkline on open; ~4*90 ints is a few KB.
const metricsCap = 90

// Warm-up cadence: right after start the ring is empty, so a dashboard opened in
// the first metricsSampleInterval would show value-only tiles with no sparkline -
// long enough to look broken. The sampler primes one reading immediately, then
// takes a few quick samples so the trend line fills within ~15s instead of ~2 min,
// before settling to the steady-state interval. The sparkline spaces points by
// index (not wall-clock), so the briefly-denser warm-up samples read fine and age
// out of the ring within the first ~18 min.
const (
	metricsWarmupSamples  = 5
	metricsWarmupInterval = 3 * time.Second
)

// ringInt is a fixed-capacity ring of ints (a time series of one metric). Push
// overwrites the oldest sample once full; series() reads oldest -> newest.
type ringInt struct {
	buf  []int
	head int // index of the next write
	n    int // samples held (<= cap)
}

func newRingInt(capacity int) ringInt { return ringInt{buf: make([]int, capacity)} }

func (r *ringInt) push(v int) {
	r.buf[r.head] = v
	r.head = (r.head + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
}

// series copies the held samples out in chronological order (oldest first).
func (r *ringInt) series() []int {
	out := make([]int, r.n)
	start := (r.head - r.n + len(r.buf)) % len(r.buf)
	for i := 0; i < r.n; i++ {
		out[i] = r.buf[(start+i)%len(r.buf)]
	}
	return out
}

// metricsStore holds the dashboard's live trend series. Stored as plain ints
// (lease count, integer %, whole ms) so the sparkline mapping stays integer-clean
// and the per-push signature is cheap. In-memory only by design: a live operator
// console, not a historian - the audit log is the durable record, and an SD-card
// write per sample would be wasteful on the Pi.
type metricsStore struct {
	mu       sync.RWMutex
	leaseCnt ringInt
	poolPct  ringInt
	keaRTT   ringInt
	uplink   ringInt
	ptp      ringInt
	pushes   uint64 // monotonic; the change signature for the live ticker
}

func newMetricsStore() *metricsStore {
	return &metricsStore{
		leaseCnt: newRingInt(metricsCap),
		poolPct:  newRingInt(metricsCap),
		keaRTT:   newRingInt(metricsCap),
		uplink:   newRingInt(metricsCap),
		ptp:      newRingInt(metricsCap),
	}
}

// push appends one sample to every series. uplink uses -1 to mean offline/no-probe;
// ptp carries the grandmaster's advertised clockClass (sync quality), or -1 when no
// GM is present.
func (m *metricsStore) push(leaseCnt, poolPct, keaRTT, uplink, ptp int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leaseCnt.push(leaseCnt)
	m.poolPct.push(poolPct)
	m.keaRTT.push(keaRTT)
	m.uplink.push(uplink)
	m.ptp.push(ptp)
	m.pushes++
}

// metricsSnapshot is an immutable copy of the series (oldest -> newest).
type metricsSnapshot struct {
	LeaseCount []int
	PoolPct    []int
	KeaRTT     []int
	Uplink     []int
	Ptp        []int
}

func (m *metricsStore) snapshot() metricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return metricsSnapshot{
		LeaseCount: m.leaseCnt.series(),
		PoolPct:    m.poolPct.series(),
		KeaRTT:     m.keaRTT.series(),
		Uplink:     m.uplink.series(),
		Ptp:        m.ptp.series(),
	}
}

// signature increments only when a new sample lands. The live ticker (4s) gates
// the stat-tiles render on it via markChanged, so between 12s samples the tiles
// are not re-rendered; publishIfChanged still suppresses an identical fragment.
func (m *metricsStore) signature() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pushes
}

// startMetricsSampler launches the always-on background sampler. Unlike the live
// ticker it runs regardless of connected clients, so the trend series are warm
// when an operator opens the dashboard.
func (s *Server) startMetricsSampler() {
	go func() {
		// Prime immediately so a dashboard opened right after start already has a
		// data point (no empty-sparkline window), then warm up quickly before the
		// steady cadence so the trend line fills in ~15s rather than ~2 min.
		s.sampleOnceSafe()
		for i := 0; i < metricsWarmupSamples; i++ {
			time.Sleep(metricsWarmupInterval)
			s.sampleOnceSafe()
		}
		t := time.NewTicker(metricsSampleInterval)
		defer t.Stop()
		for range t.C {
			s.sampleOnceSafe()
		}
	}()
}

// sampleOnceSafe wraps one sample in a recover so a transient panic (e.g. a bad
// scope/pool input) degrades that one reading instead of killing the goroutine -
// which would silently freeze every dashboard sparkline until the next restart.
func (s *Server) sampleOnceSafe() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[metrics] sampler recovered from panic: %v", r)
		}
	}()
	s.sampleMetrics()
}

// sampleMetrics takes one reading of every series. The single GetLeases also
// primes the Kea RTT (it funnels through SendCommand), so the RTT sample is the
// real cost of this very poll. On a Kea error it pushes nothing - a gap in the
// sparkline is honest; a fabricated zero would not be.
func (s *Server) sampleMetrics() {
	// System health (CPU/mem/disk) is independent of Kea - sample it FIRST so the
	// header health chip keeps updating during a Kea outage (when the operator most
	// wants to see host pressure), not after the Kea-error early-return below.
	if s.sysHealth != nil {
		s.sysHealth.sample()
	}

	leases, err := s.kea.GetLeases(1000)
	// Record Kea reachability (the HTTP transport reached the socket) regardless of
	// whether the lease query itself errored, and warn on a transition. This is the
	// runtime "DHCP Server Offline" signal.
	if changed, healthy := s.health.observeKea(s.kea.Reachable(), s.kea.LastError()); changed {
		s.onBackendChange("KEA", healthy, s.kea.LastError())
	}
	if err != nil {
		return // Kea down: skip only the lease-derived series.
	}
	rttMs := int(s.kea.LastRTT() / time.Millisecond)
	// Count only currently-held leases so the tile value and its sparkline agree
	// (Kea also returns expired-not-yet-reclaimed leases).
	active := activeLeases(leases)
	// Push the deduped device count so the tile value and its sparkline agree with the
	// dashboard card and /leases (a moved device's stale lease isn't double-counted).
	// recordLastSeen still gets the full set so last-seen tracking is unaffected.
	s.metrics.push(len(dedupeStaleLeases(active)), s.samplePoolUtil(leases), rttMs, s.uplinkProbe(), s.samplePTPClass())
	s.recordLastSeen(active)
}

// lastSeenAdvance is the minimum cltt advance (seconds) before a last_seen row is
// re-persisted. cltt only moves on a renewal (infrequent), so this collapses the
// steady state to ~zero SQLite writes between renewals - the in-memory map still
// tracks every sample for display.
const lastSeenAdvance = 60

// recordLastSeen updates the last-seen tracker from the currently-active leases: each
// lease's cltt for its MAC, and (when its client-id decodes to a switch port) for the
// flex-id key. The in-memory map always takes the freshest value; SQLite is written
// only for identities whose cltt advanced past what was last persisted.
func (s *Server) recordLastSeen(leases []kea.ActiveLease) {
	pending := make(map[string]db.LastSeen)
	s.lastSeenMu.Lock()
	for _, l := range leases {
		if l.Cltt <= 0 {
			continue
		}
		ids := make([]db.LastSeen, 0, 2)
		if mac := normalizeMAC(l.HWAddress); mac != "" {
			ids = append(ids, db.LastSeen{Identity: mac, Kind: "lease", LastSeen: l.Cltt})
		}
		if id, ok := decodePortIdentity(l.ClientID); ok {
			ids = append(ids, db.LastSeen{Identity: id.Key, Kind: "port", LastSeen: l.Cltt})
		}
		for _, e := range ids {
			if l.Cltt > s.lastSeen[e.Identity] {
				s.lastSeen[e.Identity] = l.Cltt
			}
			if l.Cltt-s.lastSeenWritten[e.Identity] >= lastSeenAdvance {
				s.lastSeenWritten[e.Identity] = l.Cltt
				pending[e.Identity] = e
			}
		}
	}
	s.lastSeenMu.Unlock()

	if err := s.sqlite.UpsertLastSeen(pending); err != nil {
		log.Printf("[last-seen] upsert failed: %v", err)
	}
}

// samplePTPClass reads the passive monitor for the headline grandmaster's
// advertised clockClass - the GM's own sync-quality figure (6 = GPS-locked, 7 =
// holdover, 248 = free-running default, ...). It returns -1 when no GM is present
// (the absent sentinel the sparkline/tooltip render as "absent"). This is the PTP
// tile's trend series: a GM that loses its reference (6 -> 7 -> 248) shows as a
// step, which mere presence never would. Only "domain N" snapshots count; the
// detector's idle "No PTP grandmaster seen" (subject = interface) is not a GM.
func (s *Server) samplePTPClass() int {
	if s.netmon == nil {
		return -1
	}
	for _, snap := range s.netmon.SnapshotAll() {
		for _, d := range snap.Detectors {
			if d.Kind != "ptp" || !strings.HasPrefix(d.Subject, "domain ") {
				continue
			}
			if cc, ok := d.Fields["clockClass"]; ok {
				return atoiDefault(cc, -1)
			}
		}
	}
	return -1
}

// samplePoolUtil computes overall DHCP-pool utilization (leased / capacity, %)
// for the active profile via the same poolDataForScope path the dashboard build
// uses, so the tile and the pool table agree. Reserves are excluded by
// poolDataForScope. Returns 0 when there is no active profile / capacity.
func (s *Server) samplePoolUtil(leases []kea.ActiveLease) int {
	var profileID int
	if err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID); err != nil {
		return 0
	}
	scopes, err := s.loadScopeConfigs(profileID)
	if err != nil {
		return 0
	}
	var pools []views.PoolRow
	for _, sc := range scopes {
		pools = append(pools, poolDataForScope(sc, leases)...)
	}
	return overallPoolUtil(pools)
}
