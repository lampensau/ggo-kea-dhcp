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
