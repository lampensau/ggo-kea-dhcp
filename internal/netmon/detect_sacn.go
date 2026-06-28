package netmon

import (
	"sort"
	"strings"
	"time"
)

// sacnPort is the E1.31 (sACN) UDP port.
const sacnPort = 5568

// vectorE131Data is the framing-layer vector for a DMP data packet. Sync and
// universe-discovery packets share port 5568 but use other vectors and a
// different layout, so we filter on this to avoid reading their bytes as a
// data packet's priority/universe.
const vectorE131Data = 0x00000002

// optStreamTerminated is the framing Options bit a source sets to cleanly stop
// transmitting a universe (E1.31 7.3). Honoring it drops the source at once
// instead of waiting out the absence timeout.
const optStreamTerminated = 0x40

// defaultSACNAbsence: a source that stops transmitting for this long is dropped.
// sACN is multicast, so it is only captured during the promiscuous duty window
// (defaultDutyOn on / defaultDutyOff off). A source seen in one window is not
// sampled again for a full off-period, so the absence MUST exceed the duty
// period or a steadily-present source would age out every cycle and churn
// presence/conflict state. We size it to ~2x the duty period.
// ponytail: clean shutdown is the fast path (optStreamTerminated); this long
// timeout only bounds the worst case where we never catch the terminate packet.
const defaultSACNAbsence = 2 * (defaultDutyOn + defaultDutyOff)

// sacnDetector inspects E1.31 lighting data. Multiple sources on a universe is
// normal and intentional (priority-based backup), so it is informational; a true
// conflict is two *different* sources (CIDs) transmitting on the same universe at
// the *same* priority - neither defers, so output flickers. Tier-2, multicast →
// needs the promiscuous duty-cycle (gated by MulticastSniff).
type sacnDetector struct {
	iface     string
	absence   time.Duration
	universes map[uint16]*sacnUniverse
}

type sacnUniverse struct {
	sources    map[string]*sacnSource
	inConflict bool
}

type sacnSource struct {
	pres        *presence
	cid         string
	name        string // last source name seen under this CID
	priority    uint8
	present     bool
	dupCID      bool // two distinct source names seen under one CID = two devices
	dupReported bool // debounce: emit the duplicate-CID event once per source
}

func newSACNDetector(iface string, absence time.Duration) *sacnDetector {
	if absence <= 0 {
		absence = defaultSACNAbsence
	}
	return &sacnDetector{iface: iface, absence: absence, universes: make(map[uint16]*sacnUniverse)}
}

func (d *sacnDetector) Consume(f Frame, now time.Time) {
	et, off, _, ok := etherInfo(f.Data)
	if !ok || et != etherTypeIPv4 {
		return
	}
	proto, _, _, l4, ok := ipv4Info(f.Data, off)
	if !ok || proto != ipProtoUDP {
		return
	}
	_, dport, payload, ok := udpPorts(f.Data, l4)
	if !ok || dport != sacnPort {
		return
	}
	p := f.Data[payload:]
	// E1.31: framing vector at offset 40; CID at root-layer offset 22 (16 bytes);
	// source name at framing offset 44 (64 bytes); priority at 108; options at
	// 112; universe at 113 (2 bytes).
	if len(p) < 115 {
		return
	}
	if be32(p, 40) != vectorE131Data {
		return // sync / discovery packet on the same port - not data
	}
	cid := hexBytes(p[22:38])
	name := trimName(p[44:108])
	priority := p[108]
	terminated := p[112]&optStreamTerminated != 0
	universe := be16(p, 113)

	u := d.universes[universe]
	if u == nil {
		if terminated {
			return // nothing to terminate
		}
		u = &sacnUniverse{sources: make(map[string]*sacnSource)}
		d.universes[universe] = u
	}
	if terminated {
		// Clean shutdown: drop the source now so a real conflict clears at once
		// rather than lingering for the absence timeout.
		delete(u.sources, cid)
		return
	}
	src := u.sources[cid]
	if src == nil {
		src = &sacnSource{pres: newPresence(0, d.absence), cid: cid}
		u.sources[cid] = src
	}
	// Two devices misconfigured with the same CID give it away by disagreeing on
	// the source name (a single device never changes its own name).
	if name != "" && src.name != "" && name != src.name {
		src.dupCID = true
	}
	if name != "" {
		src.name = name
	}
	src.priority = priority
	src.pres.sighting(now)
}

// trimName decodes a NUL-padded E1.31 source-name field.
func trimName(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// hexBytes formats a byte slice as lowercase hex (for the 16-byte CID).
func hexBytes(b []byte) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, len(b)*2)
	for _, c := range b {
		buf = append(buf, hex[c>>4], hex[c&0x0f])
	}
	return string(buf)
}

func (d *sacnDetector) Tick(now time.Time) []Event {
	var events []Event
	univs := make([]int, 0, len(d.universes))
	for n := range d.universes {
		univs = append(univs, int(n))
	}
	sort.Ints(univs)

	for _, un := range univs {
		universe := uint16(un)
		u := d.universes[universe]
		for cid, src := range u.sources {
			switch src.pres.transition(now) {
			case 1:
				src.present = true
			case -1:
				src.present = false
				delete(u.sources, cid)
				continue
			}
			if src.present && src.dupCID && !src.dupReported {
				src.dupReported = true
				events = append(events, Event{
					Action:   "sACN duplicate CID",
					Target:   d.iface + " universe " + itoa(int(universe)),
					Before:   "ok",
					After:    "two devices share CID " + src.cid[:8],
					Severity: SevWarn,
				})
			}
		}
		conflict := u.conflictNow()
		switch {
		case conflict && !u.inConflict:
			u.inConflict = true
			events = append(events, Event{
				Action:   "sACN universe conflict",
				Target:   d.iface + " universe " + itoa(int(universe)),
				Before:   "ok",
				After:    u.conflictDetail(),
				Severity: SevWarn,
			})
		case !conflict && u.inConflict:
			u.inConflict = false
			events = append(events, Event{
				Action:   "sACN universe conflict cleared",
				Target:   d.iface + " universe " + itoa(int(universe)),
				Before:   "conflict",
				After:    "ok",
				Severity: SevInfo,
			})
		}
		// Reclaim a universe once its sources have all drained and it is not in a
		// (still-displayed) conflict - otherwise the map and the per-tick iteration
		// grow with every universe ever briefly seen on a long-running show.
		if len(u.sources) == 0 && !u.inConflict {
			delete(d.universes, universe)
		}
	}
	return events
}

// conflictNow reports whether two distinct present sources share a priority.
func (u *sacnUniverse) conflictNow() bool {
	byPrio := make(map[uint8]int)
	for _, s := range u.sources {
		if s.present {
			byPrio[s.priority]++
		}
	}
	for _, n := range byPrio {
		if n >= 2 {
			return true
		}
	}
	return false
}

// conflictDetail describes the contending sources for the audit log: the shared
// priority and each source's name + CID prefix (e.g. "priority 100: 'ggo-A'
// (a1a1a1a1), 'ggo-B' (b2b2b2b2)").
func (u *sacnUniverse) conflictDetail() string {
	byPrio := make(map[uint8][]*sacnSource)
	for _, s := range u.sources {
		if s.present {
			byPrio[s.priority] = append(byPrio[s.priority], s)
		}
	}
	for prio, ss := range byPrio {
		if len(ss) < 2 {
			continue
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i].cid < ss[j].cid })
		parts := make([]string, 0, len(ss))
		for _, s := range ss {
			label := s.cid[:8]
			if s.name != "" {
				label = "'" + s.name + "' (" + s.cid[:8] + ")"
			}
			parts = append(parts, label)
		}
		return "priority " + itoa(int(prio)) + ": " + strings.Join(parts, ", ")
	}
	return "two sources at equal priority"
}

// dupNow reports whether a present source shows the duplicate-CID signature.
func (u *sacnUniverse) dupNow() bool {
	for _, s := range u.sources {
		if s.present && s.dupCID {
			return true
		}
	}
	return false
}

func (u *sacnUniverse) presentCount() int {
	n := 0
	for _, s := range u.sources {
		if s.present {
			n++
		}
	}
	return n
}

func (d *sacnDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "sacn", Subject: d.iface}
	var conflicts, multi, active, dups int
	var firstConflict, firstDup uint16
	univs := make([]int, 0, len(d.universes))
	for n := range d.universes {
		univs = append(univs, int(n))
	}
	sort.Ints(univs)
	for _, un := range univs {
		u := d.universes[uint16(un)]
		c := u.presentCount()
		if c == 0 {
			continue
		}
		active++
		if u.dupNow() {
			if dups == 0 {
				firstDup = uint16(un)
			}
			dups++
		}
		if u.conflictNow() {
			if conflicts == 0 {
				firstConflict = uint16(un)
			}
			conflicts++
		} else if c > 1 {
			multi++
		}
	}
	switch {
	case conflicts > 0:
		s.Severity = SevWarn
		s.Subject = "universe " + itoa(int(firstConflict))
		s.Text = "sACN conflict on universe " + itoa(int(firstConflict))
		s.Fields = map[string]string{"conflicts": itoa(conflicts)}
	case dups > 0:
		s.Severity = SevWarn
		s.Subject = "universe " + itoa(int(firstDup))
		s.Text = "sACN duplicate CID on universe " + itoa(int(firstDup))
		s.Fields = map[string]string{"duplicate_cid": itoa(dups)}
	case active > 0:
		s.Severity = SevInfo
		s.Text = itoa(active) + " active sACN " + plural(active, "universe", "universes")
		s.Fields = map[string]string{"universes": itoa(active), "backed_up": itoa(multi)}
	default:
		// Neutral, not a green "all clear": sACN data is multicast, so when
		// multicast-sniff is off (or its groups aren't joined) "none seen" means
		// "not inspected", not "healthy".
		s.Severity = SevInfo
		s.Text = "No sACN traffic seen"
	}
	return s
}

// plural picks the singular/plural form for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
