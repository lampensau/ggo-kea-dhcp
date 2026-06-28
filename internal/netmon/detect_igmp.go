package netmon

import "time"

// defaultIGMPAbsence is how long the box goes without seeing any IGMP query
// before it warns the querier is gone. A querier typically queries every
// 60–125s, so 300s tolerates a couple of missed intervals before crying wolf
// (overridable via netmon_igmp_timeout).
const defaultIGMPAbsence = 300 * time.Second

// igmpDetector tracks the multicast querier. A switch running IGMP snooping
// prunes multicast unless a querier is present, which silently drops Dante/PTP/
// Green-GO audio - so the *absence* of a querier (after one was seen) is the
// warning, not its presence. Passive: IPv4 proto 2, type 0x11 (membership query).
type igmpDetector struct {
	iface string
	pres  *presence

	everPresent bool
	querierIP   string
	version     int
	queries     int
}

func newIGMPDetector(iface string, absence time.Duration) *igmpDetector {
	if absence <= 0 {
		absence = defaultIGMPAbsence
	}
	// confirmAfter 0: a single general query proves a querier exists.
	return &igmpDetector{iface: iface, pres: newPresence(0, absence)}
}

func (d *igmpDetector) Consume(f Frame, now time.Time) {
	et, off, _, ok := etherInfo(f.Data)
	if !ok || et != etherTypeIPv4 {
		return
	}
	proto, src, _, l4, ok := ipv4Info(f.Data, off)
	if !ok || proto != ipProtoIGMP {
		return
	}
	if l4 >= len(f.Data) || f.Data[l4] != 0x11 { // membership query
		return
	}
	// Bound the IGMP message by the IP total-length, NOT len(f.Data): Ethernet
	// pads short frames to 60 bytes, so a real 8-byte IGMPv2 query trails padding
	// that would otherwise be misread as a longer (v3) message.
	igmpLen := len(f.Data) - l4
	if total := int(be16(f.Data, off+2)); total > 0 {
		if n := total - (l4 - off); n >= 0 && n < igmpLen {
			igmpLen = n
		}
	}
	d.querierIP = ipString(src)
	d.version = igmpVersion(f.Data, l4, igmpLen)
	d.queries++
	d.pres.sighting(now)
}

// igmpVersion sniffs the query version: maxResp 0 ⇒ v1, a 12+ byte message ⇒ v3,
// otherwise v2. msgLen is the IGMP message length (IP total-length bounded, so
// Ethernet padding does not inflate it).
func igmpVersion(b []byte, off, msgLen int) int {
	if msgLen >= 12 {
		return 3
	}
	if off+1 < len(b) && b[off+1] == 0 {
		return 1
	}
	return 2
}

func (d *igmpDetector) Tick(now time.Time) []Event {
	switch d.pres.transition(now) {
	case 1:
		d.everPresent = true
		return []Event{{
			Action:   "IGMP querier present",
			Target:   d.querierIP,
			Before:   "absent",
			After:    "querier on " + d.iface,
			Severity: SevOK,
		}}
	case -1:
		return []Event{{
			Action:   "IGMP querier lost",
			Target:   d.querierIP,
			Before:   "present",
			After:    "absent",
			Severity: SevWarn,
		}}
	}
	return nil
}

func (d *igmpDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "igmp", Subject: d.iface}
	switch {
	case d.pres.isPresent():
		s.Severity = SevOK
		// Subject stays the iface (not the querier IP) so the detail line can say
		// "on eth0"; the querier address lives in Fields. A snooping/proxy querier
		// legitimately sources from 0.0.0.0 - that is presence, not an address.
		s.Text = "IGMP querier present"
		s.Fields = map[string]string{
			"querier": d.querierIP,
			"version": "v" + itoa(d.version),
			"queries": itoa(d.queries),
		}
	case d.everPresent:
		s.Severity = SevWarn
		s.Text = "IGMP querier lost - multicast may be pruned"
	default:
		s.Severity = SevInfo
		s.Text = "No IGMP querier observed yet"
	}
	return s
}
