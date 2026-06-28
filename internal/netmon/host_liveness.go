package netmon

import (
	"sync"
	"time"
)

// hostLivenessWindow is how long after a host's last frame we still consider it
// "online". Green-GO devices are chatty (PTP every 1-2s, audio multicast, periodic
// ARP/lease renewals), all of which the monitor sees even at LevelNoPromisc, so a
// live device refreshes well within this window; a powered-off device ages out.
const hostLivenessWindow = 120 * time.Second

// hostTracker records the last time each source MAC was seen on the wire. It is the
// passive basis for the dashboard's per-lease online/offline indicator: "online" =
// this MAC sent a frame within hostLivenessWindow. Updated on every captured frame
// (cheap map write); read + pruned once per snapshot tick.
type hostTracker struct {
	mu   sync.Mutex
	seen map[[6]byte]time.Time
}

func newHostTracker() *hostTracker { return &hostTracker{seen: make(map[[6]byte]time.Time)} }

// record stamps the frame's source MAC as seen at now. now is the real (wall)
// clock - liveness is about elapsed real time, not the frame-clock the absence
// detectors use.
func (h *hostTracker) record(f Frame, now time.Time) {
	if h == nil {
		return
	}
	mac, ok := srcMAC(f.Data)
	if !ok {
		return
	}
	h.mu.Lock()
	h.seen[mac] = now
	h.mu.Unlock()
}

// liveWithin returns the MACs seen within hostLivenessWindow of now (lowercase,
// colon-separated) and prunes the entries that have aged out, so the map stays
// bounded by the number of currently-live hosts.
func (h *hostTracker) liveWithin(now time.Time) []string {
	if h == nil {
		return nil
	}
	cutoff := now.Add(-hostLivenessWindow)
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.seen))
	for mac, t := range h.seen {
		if t.Before(cutoff) {
			delete(h.seen, mac)
			continue
		}
		out = append(out, macString(mac))
	}
	return out
}
