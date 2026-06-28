package netmon

import (
	"sort"
	"time"
)

// defaultPTPAbsence: PTP Announce is typically sent every 1–2s, so a few seconds
// of silence already means the GM is gone, but we allow margin against bursty
// loss / duty-cycle gaps before warning.
const defaultPTPAbsence = 15 * time.Second

// ptpChurnWindow / ptpChurnThreshold: this many distinct GM appearances within
// the window in one domain is grandmaster contention (BMCA thrash), worth a warn
// even while a GM is nominally present.
const (
	ptpChurnWindow    = 60 * time.Second
	ptpChurnThreshold = 3
)

// ptpDetector tracks PTP grandmasters per domain. Audio clock sync depends on a
// stable GM; the failure modes are a domain that *had* a GM going empty (sync
// lost) and rapid GM-identity churn (contention). Multiple simultaneous GMs is
// normal BMCA failover → info, not a warning. We do not assume a domain number
// (Green-GO defaults to 0 but it is user-editable) - domains are discovered from
// the wire. Announce arrives as L2 0x88F7 or UDP 319/320 (multicast → needs the
// promiscuous duty-cycle, gated by MulticastSniff).
type ptpDetector struct {
	iface   string
	absence time.Duration
	domains map[uint8]*ptpDomain
}

// ptpDomain is intentionally NOT reclaimed when its GMs drain: an
// everPopulated-but-empty domain is precisely the "grandmaster lost" warn state
// the card must keep showing. Domains are bounded by the protocol (≤128) and in
// practice number one or two, so retaining them is not a leak - unlike sACN
// universes, which are reclaimed (see detect_sacn.go).
type ptpDomain struct {
	gms           map[uint64]*ptpGM
	everPopulated bool
	lossTimes     []time.Time // recent GM losses (churn = repeated turnover, not concurrent breadth)
}

type ptpGM struct {
	pres       *presence
	identity   string
	priority1  uint8
	priority2  uint8
	clockClass uint8 // grandmasterClockQuality.clockClass - the advertised sync quality
	present    bool
}

func newPTPDetector(iface string, absence time.Duration) *ptpDetector {
	if absence <= 0 {
		absence = defaultPTPAbsence
	}
	return &ptpDetector{iface: iface, absence: absence, domains: make(map[uint8]*ptpDomain)}
}

func (d *ptpDetector) Consume(f Frame, now time.Time) {
	ptp, ok := ptpPayload(f.Data)
	if !ok || len(ptp) < 61 {
		return
	}
	if ptp[0]&0x0f != 0x0b { // Announce
		return
	}
	domain := ptp[4]
	priority1 := ptp[47]
	// grandmasterClockQuality is the 4 bytes at offset 48; its first byte is
	// clockClass (IEEE 1588-2008 Table 5): the GM's advertised sync quality - 6 =
	// locked to a primary reference (e.g. GPS), 7 = holdover, 248 = free-running
	// default, etc. It is the most operator-meaningful PTP health signal we can read
	// passively (we cannot measure true offset without being a slave).
	clockClass := ptp[48]
	priority2 := ptp[52]
	identity := be64(ptp, 53)

	dom := d.domains[domain]
	if dom == nil {
		dom = &ptpDomain{gms: make(map[uint64]*ptpGM)}
		d.domains[domain] = dom
	}
	gm := dom.gms[identity]
	if gm == nil {
		gm = &ptpGM{pres: newPresence(0, d.absence), identity: hex64(identity)}
		dom.gms[identity] = gm
	}
	gm.priority1 = priority1
	gm.priority2 = priority2
	gm.clockClass = clockClass
	gm.pres.sighting(now)
}

// ptpPayload returns the PTP message bytes for an L2 (0x88F7) or UDP 319/320
// frame, and whether one was found.
func ptpPayload(b []byte) ([]byte, bool) {
	et, off, _, ok := etherInfo(b)
	if !ok {
		return nil, false
	}
	if et == etherTypePTP {
		return b[off:], true
	}
	if et != etherTypeIPv4 {
		return nil, false
	}
	proto, _, _, l4, ok := ipv4Info(b, off)
	if !ok || proto != ipProtoUDP {
		return nil, false
	}
	_, dport, payload, ok := udpPorts(b, l4)
	if !ok || (dport != 319 && dport != 320) {
		return nil, false
	}
	return b[payload:], true
}

func (d *ptpDetector) Tick(now time.Time) []Event {
	var events []Event
	domainNums := make([]int, 0, len(d.domains))
	for n := range d.domains {
		domainNums = append(domainNums, int(n))
	}
	sort.Ints(domainNums)

	for _, dn := range domainNums {
		domain := uint8(dn)
		dom := d.domains[domain]
		for id, gm := range dom.gms {
			switch gm.pres.transition(now) {
			case 1:
				gm.present = true
				dom.everPopulated = true
				events = append(events, Event{
					Action:   "PTP grandmaster seen",
					Target:   d.iface + " domain " + itoa(int(domain)),
					Before:   "none",
					After:    gm.identity,
					Severity: SevInfo,
				})
			case -1:
				gm.present = false
				delete(dom.gms, id)
				// Churn = GM *turnover* over time (a GM dropped/re-elected), NOT the
				// number of GMs present at once: several concurrent backup GMs is a
				// normal BMCA failover stack (info), not contention. So we record the
				// loss, never the appearance.
				dom.lossTimes = append(dom.lossTimes, now)
				sev := SevInfo
				if d.domainGMCount(domain) == 0 {
					sev = SevWarn // last GM gone → sync lost
				}
				events = append(events, Event{
					Action:   "PTP grandmaster lost",
					Target:   d.iface + " domain " + itoa(int(domain)),
					Before:   gm.identity,
					After:    "none",
					Severity: sev,
				})
			}
		}
		// Churn: prune losses outside the window, warn if too many remain.
		dom.lossTimes = pruneBefore(dom.lossTimes, now.Add(-ptpChurnWindow))
	}
	return events
}

func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func (d *ptpDetector) domainGMCount(domain uint8) int {
	n := 0
	for _, gm := range d.domains[domain].gms {
		if gm.present {
			n++
		}
	}
	return n
}

func (d *ptpDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "ptp", Subject: d.iface}

	// Pick the most severe domain for the headline; summarize the rest in Fields.
	type domState struct {
		domain uint8
		count  int
		churn  bool
		empty  bool // empty after having been populated
		gm     *ptpGM
	}
	var states []domState
	for dn, dom := range d.domains {
		count := d.domainGMCount(dn)
		st := domState{domain: dn, count: count, churn: len(dom.lossTimes) >= ptpChurnThreshold}
		if count == 0 {
			st.empty = dom.everPopulated
		} else {
			for _, gm := range dom.gms {
				if gm.present {
					st.gm = gm
					break
				}
			}
		}
		states = append(states, st)
	}
	if len(states) == 0 {
		s.Severity = SevInfo
		s.Text = "No PTP grandmaster seen"
		return s
	}
	sort.Slice(states, func(i, j int) bool { return states[i].domain < states[j].domain })

	// Severity precedence: empty(warn) / churn(warn) > multi-GM(info) > single(ok).
	sev := SevOK
	text := ""
	subject := d.iface
	var headGM *ptpGM // the present GM the headline refers to (nil when lost/churning)
	for _, st := range states {
		switch {
		case st.empty || st.churn:
			if sev != SevWarn {
				sev = SevWarn
				if st.empty {
					text = "PTP grandmaster lost in domain " + itoa(int(st.domain))
				} else {
					text = "PTP grandmaster contention in domain " + itoa(int(st.domain))
				}
				subject = "domain " + itoa(int(st.domain))
				headGM = st.gm
			}
		case st.count > 1:
			if sev == SevOK {
				sev = SevInfo
				text = itoa(st.count) + " PTP grandmasters in domain " + itoa(int(st.domain)) + " (failover)"
				subject = "domain " + itoa(int(st.domain))
				headGM = st.gm
			}
		default: // single GM
			if sev == SevOK && text == "" && st.gm != nil {
				text = "PTP GM " + st.gm.identity + " (domain " + itoa(int(st.domain)) + ")"
				subject = "domain " + itoa(int(st.domain))
				headGM = st.gm
			}
		}
	}
	s.Severity = sev
	s.Text = text
	s.Subject = subject
	s.Fields = map[string]string{"domains": itoa(len(states))}
	// Surface the headline GM's advertised clock quality so the dashboard can show a
	// real statistic (clock class / lock state) rather than mere presence.
	if headGM != nil {
		s.Fields["clockClass"] = itoa(int(headGM.clockClass))
	}
	return s
}
