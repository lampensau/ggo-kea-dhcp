package netmon

import (
	"sort"
	"sync"
)

// Level is the governor's load-shedding level, carried in a Snapshot so the card
// states the active fidelity honestly ("multicast inspection paused - high load").
type Level int

const (
	// LevelFull (L0): full fidelity, promiscuous duty-cycle allowed.
	LevelFull Level = iota
	// LevelNoPromisc (L1): promiscuous dropped - the high-value non-promiscuous
	// detectors (IGMP, rogue-DHCP, LLDP, BPDU) keep running on the narrow BPF.
	LevelNoPromisc
	// LevelCountersOnly (L2): only sysfs counter deltas (storm) are read.
	LevelCountersOnly
	// LevelPaused (L3): capture paused entirely; auto-recovers on sustained calm.
	LevelPaused
)

func (l Level) String() string {
	switch l {
	case LevelFull:
		return "full"
	case LevelNoPromisc:
		return "no-promiscuous"
	case LevelCountersOnly:
		return "counters-only"
	case LevelPaused:
		return "paused"
	default:
		return "unknown"
	}
}

// Snapshot is the per-interface aggregate the dashboard reads: each detector's
// current signal plus the governor level and an availability note. It is the only
// thing crossing from the monitor goroutines to the web layer.
type Snapshot struct {
	Iface     string
	Available bool   // false in dev-mode (no socket) or when permanently degraded
	Note      string // honest state when not fully available
	Level     Level
	Detectors []DetectorSnapshot
	// LiveMACs are the source MACs seen on this interface within the liveness window
	// (lowercase, colon-separated) - the passive basis for per-lease online/offline.
	LiveMACs []string
}

// SnapshotStore is the concurrency boundary between the monitor goroutines
// (writers, one per interface) and the web layer (reader). Per-interface
// snapshots only - the DB is never involved.
type SnapshotStore struct {
	mu      sync.RWMutex
	byIface map[string]Snapshot
}

// NewSnapshotStore returns an empty store.
func NewSnapshotStore() *SnapshotStore {
	return &SnapshotStore{byIface: make(map[string]Snapshot)}
}

// Update replaces the snapshot for iface (called once per monitor tick).
func (s *SnapshotStore) Update(iface string, snap Snapshot) {
	s.mu.Lock()
	s.byIface[iface] = snap
	s.mu.Unlock()
}

// Remove drops an interface's snapshot (on Stop / profile switch) so a stale card
// row does not linger after monitoring for that interface ends.
func (s *SnapshotStore) Remove(iface string) {
	s.mu.Lock()
	delete(s.byIface, iface)
	s.mu.Unlock()
}

// SnapshotAll returns every interface's snapshot, sorted by interface name so the
// card row order is stable across renders.
func (s *SnapshotStore) SnapshotAll() []Snapshot {
	s.mu.RLock()
	out := make([]Snapshot, 0, len(s.byIface))
	for _, snap := range s.byIface {
		out = append(out, snap)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}
