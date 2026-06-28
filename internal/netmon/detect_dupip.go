package netmon

import (
	"sort"
	"time"
)

// defaultDeclineAbsence: a conflict shown for a while after the last DECLINE so a
// flapping client doesn't make the card blink.
const defaultDeclineAbsence = 300 * time.Second

// duplicateIPDetector spots address conflicts passively by counting DHCPDECLINEs
// (option 53 = 4): a client sends one when its ARP probe finds the offered
// address already in use, so a DECLINE is direct evidence of a duplicate IP. The
// conflicted address rides in option 50. We deliberately keep this passive - the
// RFC-5227 active ARP-probe path described in the plan is omitted in v1 to stay
// strictly observe-only (no injected packets), and the DECLINE signal already
// names the conflicted address.
type duplicateIPDetector struct {
	iface     string
	absence   time.Duration
	conflicts map[[4]byte]*conflictEntry
}

type conflictEntry struct {
	pres     *presence
	ip       string
	declines int
	present  bool
}

func newDuplicateIPDetector(iface string, absence time.Duration) *duplicateIPDetector {
	if absence <= 0 {
		absence = defaultDeclineAbsence
	}
	return &duplicateIPDetector{
		iface:     iface,
		absence:   absence,
		conflicts: make(map[[4]byte]*conflictEntry),
	}
}

func (d *duplicateIPDetector) Consume(f Frame, now time.Time) {
	et, off, _, ok := etherInfo(f.Data)
	if !ok || et != etherTypeIPv4 {
		return
	}
	proto, _, _, l4, ok := ipv4Info(f.Data, off)
	if !ok || proto != ipProtoUDP {
		return
	}
	// A DHCPDECLINE is always client→server, so it lands on dport 67. (We don't
	// accept sport 67 here - a server never originates a DECLINE.)
	_, dport, payload, ok := udpPorts(f.Data, l4)
	if !ok || dport != 67 {
		return
	}
	const dhcpOptsOff = 240
	if payload+dhcpOptsOff > len(f.Data) {
		return
	}
	opts := parseDHCPOptions(f.Data[payload+dhcpOptsOff:])
	if opts.msgType != 4 || !opts.hasRequestedIP { // DHCPDECLINE with a declined addr
		return
	}
	e := d.conflicts[opts.requestedIP]
	if e == nil {
		e = &conflictEntry{pres: newPresence(0, d.absence), ip: ipString(opts.requestedIP)}
		d.conflicts[opts.requestedIP] = e
	}
	e.declines++
	e.pres.sighting(now)
}

func (d *duplicateIPDetector) Tick(now time.Time) []Event {
	var events []Event
	for ip, e := range d.conflicts {
		switch e.pres.transition(now) {
		case 1:
			e.present = true
			events = append(events, Event{
				Action:   "Address conflict detected",
				Target:   e.ip,
				Before:   "none",
				After:    "DHCPDECLINE on " + d.iface,
				Severity: SevWarn,
			})
		case -1:
			e.present = false
			events = append(events, Event{
				Action:   "Address conflict cleared",
				Target:   e.ip,
				Before:   "conflict",
				After:    "none",
				Severity: SevInfo,
			})
			delete(d.conflicts, ip)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].After < events[j].After })
	return events
}

func (d *duplicateIPDetector) Snapshot() DetectorSnapshot {
	var active []*conflictEntry
	for _, e := range d.conflicts {
		if e.present {
			active = append(active, e)
		}
	}
	s := DetectorSnapshot{Kind: "duplicate_ip", Subject: d.iface}
	if len(active) == 0 {
		s.Severity = SevOK
		s.Text = "No address conflicts"
		return s
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ip < active[j].ip })
	first := active[0]
	s.Severity = SevWarn
	s.Subject = first.ip
	s.Text = "Address conflict: " + first.ip
	if len(active) > 1 {
		s.Text = itoa(len(active)) + " address conflicts"
	}
	s.Fields = map[string]string{"address": first.ip, "declines": itoa(first.declines)}
	return s
}
