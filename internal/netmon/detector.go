package netmon

import "time"

// Severity ranks a detector signal so the templ card can map it to color/icon.
// The backend emits a severity, never HTML - presentation is the card's job
// (the "appropriate signals the frontend can convert" contract).
type Severity string

const (
	SevOK    Severity = "ok"
	SevInfo  Severity = "info"
	SevWarn  Severity = "warn"
	SevError Severity = "error"
)

// DetectorSnapshot is one detector's current machine-readable signal. Kind names
// the detector ("igmp", "lldp", …); Subject is a stable identity (iface / IP /
// MAC / domain) the UI can key on; Text is short human copy; Fields carries extra
// machine-readable detail the card may render (switch port, server IP+OUI, …).
// No pre-baked presentation.
type DetectorSnapshot struct {
	Kind     string
	Severity Severity
	Subject  string
	Text     string
	Fields   map[string]string
}

// Detector folds captured frames into state on the monitor goroutine and reports
// it two deliberately decoupled ways:
//
//   - Snapshot() - the current display signal, read every monitor tick and pushed
//     to the dashboard. Never touches the DB.
//   - Tick(now)  - advances time-based state (absence timeouts, debounce) and
//     returns Events ONLY on a debounced transition, so the audit log gets one
//     row per real change, never one per tick.
//
// Consume must copy out the small fields it needs from f.Data and never retain
// the slice (it aliases a reusable read buffer).
type Detector interface {
	Consume(f Frame, now time.Time)
	Tick(now time.Time) []Event
	Snapshot() DetectorSnapshot
}

// Presence-map ceilings. Every map keyed by a wire field an on-LAN attacker can
// forge enforces a hard entry cap, independent of the governor's load shedding,
// so a flood of unique spoofed keys evicts the once-seen (therefore stalest)
// fakes instead of growing without bound. Sized generously above any legitimate
// population. The full family and its attacker-controlled key:
//   - rogueDHCP.servers          DHCP server-id       maxRogueServers
//   - staticInPool.hosts         ARP sender IP        maxStaticPoolHosts
//   - greengo.devices            device MAC           maxGgoDevices
//   - greengoH.configs           config id            maxGgoConfigs
//   - ptp.<domain>.gms           PTP clock identity   maxPTPGMs (domain map is uint8-keyed)
//   - sacn.universes / .sources  universe + CID       maxSACNUniverses / maxSACNSourcesPerUniverse
//   - dupIP.conflicts            option-50 IP         maxDupIPConflicts
//   - hostTracker.seen           source MAC           maxHostLiveness
//   - multicastJoiner.joined     sACN universe group  maxJoinedGroups (also bounds the PACKET_ADD_MEMBERSHIP storm)
const (
	maxRogueServers    = 64
	maxStaticPoolHosts = 1024
	maxGgoDevices      = 512
	maxGgoConfigs      = 256
	maxPTPGMs          = 32 // per domain; the domain map itself is uint8-keyed (bounded)

	maxSACNUniverses          = 1024
	maxSACNSourcesPerUniverse = 16
	maxDupIPConflicts         = 1024
	maxHostLiveness           = 4096
	maxJoinedGroups           = 256
)

// evictStalest makes room in a full presence map by deleting the entry with the
// oldest last-seen time. Under a spoof flood each fake key is seen once, so the
// fakes are the stalest and real, recently-sighted entries survive.
// ponytail: O(n) scan on insert at cap; fine at these sizes, switch to a heap
// only if caps ever grow past a few thousand.
func evictStalest[K comparable, V any](m map[K]V, lastSeen func(V) time.Time) {
	first := true
	var oldK K
	var oldT time.Time
	for k, v := range m {
		if t := lastSeen(v); first || t.Before(oldT) {
			oldK, oldT, first = k, t, false
		}
	}
	if !first {
		delete(m, oldK)
	}
}

// presence is the shared edge-trigger helper detectors use to track whether a
// single subject (a querier, an LLDP neighbor, a squatter) is currently present.
//
// A run of sightings must span confirmAfter before presence is *confirmed*
// (debounce - one stray frame does not flip it); once confirmed, no sighting for
// absenceAfter clears it. transition() reports only the confirmed-state edges, so
// a detector emits exactly one Event per real change and nothing on a transient
// flip. confirmAfter == 0 confirms on the first sighting (used where a single
// frame is authoritative, e.g. an IGMP general query proves a querier exists).
type presence struct {
	confirmAfter time.Duration
	absenceAfter time.Duration

	present  bool      // confirmed state
	seen     bool      // any sighting recorded yet
	runStart time.Time // first sighting of the current uninterrupted run
	lastSeen time.Time // most recent sighting
}

func newPresence(confirmAfter, absenceAfter time.Duration) *presence {
	return &presence{confirmAfter: confirmAfter, absenceAfter: absenceAfter}
}

// sighting records that the subject was observed at now. A gap longer than
// absenceAfter since the last sighting starts a fresh run, so confirmAfter
// measures continuous presence rather than counting a sighting from minutes ago.
func (p *presence) sighting(now time.Time) {
	if !p.seen || now.Sub(p.lastSeen) > p.absenceAfter {
		p.runStart = now
	}
	p.lastSeen = now
	p.seen = true
}

// transition recomputes the confirmed state at now and returns +1 when it just
// became present, -1 when it just became absent, 0 otherwise. Call it once per
// Tick after folding in that tick's sightings.
func (p *presence) transition(now time.Time) int {
	if p.present {
		if !p.seen || now.Sub(p.lastSeen) > p.absenceAfter {
			p.present = false
			return -1
		}
		return 0
	}
	if p.seen && now.Sub(p.lastSeen) <= p.absenceAfter && now.Sub(p.runStart) >= p.confirmAfter {
		p.present = true
		return 1
	}
	return 0
}

func (p *presence) isPresent() bool { return p.present }

// sustainedFor reports whether the subject is present AND its current uninterrupted
// run of sightings has spanned at least d - i.e. it has been seen repeatedly over
// time, not merely confirmed off a single frame kept "warm" through the absence
// window. A caller gating a loud, high-cost escalation (e.g. the one-click DHCP
// stand-down) on genuine, sustained presence uses this so one stray/forged frame
// can't trip it, while the ordinary present/Snapshot signal stays immediate.
func (p *presence) sustainedFor(d time.Duration) bool {
	return p.present && p.lastSeen.Sub(p.runStart) >= d
}
