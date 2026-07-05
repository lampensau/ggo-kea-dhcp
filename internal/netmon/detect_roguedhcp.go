package netmon

import (
	"sort"
	"time"
)

// defaultRogueAbsence: a competing server is volatile, but we keep a sighting
// "warm" for a while so a server that offers intermittently still shows as
// present rather than flapping.
const defaultRogueAbsence = 120 * time.Second

// rogueSustainedAfter is how long a rogue server's run of sightings must span before
// the snapshot reports it as sustained (Fields["sustained"]="1"). Presence itself is
// confirmed on the first frame (the Network Health row is immediate), but the loud
// one-click stand-down banner keys off sustained presence: a single spoofed OFFER -
// trivially forgeable by anything on the segment - stays "warm" for the absence window
// yet never accumulates span, so it can't escalate to the fleet-outage control.
const rogueSustainedAfter = 30 * time.Second

// rogueDHCPDetector flags any DHCP server other than us answering on the wire - a
// competing server hands clients wrong addresses/gateways and breaks the show.
// It self-suppresses by our own source MAC, not the option-54 server-id: the
// server-id is an attacker-controlled field, so a rogue that forges it to the
// box's IP would evade an IP-keyed filter entirely; the source MAC is an L2 fact
// (spoofing it is harder and switch-detectable). One physical NIC MAC also covers
// every served scope, tagged or not - all our OFFERs egress the same eth0 MAC -
// so a mixed untagged+VLAN box never self-flags its own per-VLAN offers. It
// reports the offender's IP + MAC/OUI. High severity. Passive (UDP sport 67,
// OFFER/ACK). During ONBOARDING the same detector backs the wizard's shield badge
// via RogueProbe, keyed on eth0's MAC (the box already serves its onboarding pool).
//
// Scope of what this reliably sees (do not overstate the guarantee): on a switched
// network - the appliance's normal deployment - it detects a rogue's BROADCAST
// OFFERs and any OFFER/ACK directed at the box itself. It CANNOT see a rogue that
// only unicasts OFFER/ACK straight to other clients: the switch forwards those out
// the victim's port, not ours, so they never reach the Pi. Catching that case
// needs switch port mirroring (a SPAN port); promiscuous mode does not fix it,
// because it relaxes only our NIC's receive filter, not the switch's forwarding.
//
// Self-verification is mandatory: if the box's own NIC MAC could not be read
// (macKnown=false), the detector CANNOT tell its own OFFERs apart from a rogue's,
// so it degrades to Unverified - it suppresses all emission rather than phantom-
// flag the appliance itself (a phantom rogue could trip the shield stand-down and
// self-inflict an outage). On the Pi net.InterfaceByName supplies the MAC; this
// path is the dev-sandbox / iface-down fallback.
type rogueDHCPDetector struct {
	iface      string
	selfMAC    [6]byte
	selfMACSet bool
	servedVID  int // this monitor's served VLAN (0 = untagged eth0); a foreign VID is ignored
	absence    time.Duration
	servers    map[[4]byte]*rogueServer
}

type rogueServer struct {
	pres    *presence
	ip      string
	mac     string
	present bool
}

func newRogueDHCPDetector(iface string, selfMAC [6]byte, macKnown bool, servedVID int, absence time.Duration) *rogueDHCPDetector {
	if absence <= 0 {
		absence = defaultRogueAbsence
	}
	return &rogueDHCPDetector{
		iface:      iface,
		selfMAC:    selfMAC,
		selfMACSet: macKnown,
		servedVID:  servedVID,
		absence:    absence,
		servers:    make(map[[4]byte]*rogueServer),
	}
}

func (d *rogueDHCPDetector) Consume(f Frame, now time.Time) {
	// Without our own MAC we cannot separate the box's own OFFERs from a rogue's, so
	// we emit nothing rather than phantom-flag the appliance (see the type doc). The
	// Snapshot reports Unverified in this state.
	if !d.selfMACSet {
		return
	}
	et, off, vid, ok := etherInfo(f.Data)
	if !ok || et != etherTypeIPv4 {
		return
	}
	// Only judge servers on the VLAN this monitor serves. An eth0 (untagged, vid 0)
	// socket also sees in-band-tagged frames leaking off the trunk; without this the
	// untagged monitor would flag a rogue that belongs to a tagged scope's own
	// monitor - double-counting one rogue, or raising the loud banner for a server
	// on a VLAN we do not even serve. Mirrors the Green-GO detectors' servedVID gate.
	if effectiveVID(vid, f) != d.servedVID {
		return
	}
	proto, _, _, l4, ok := ipv4Info(f.Data, off)
	if !ok || proto != ipProtoUDP {
		return
	}
	sport, _, payload, ok := udpPorts(f.Data, l4)
	if !ok || sport != 67 {
		return
	}
	// DHCP options begin after the 236-byte BOOTP header + 4-byte magic cookie.
	const dhcpOptsOff = 240
	if payload+dhcpOptsOff > len(f.Data) {
		return
	}
	opts := parseDHCPOptions(f.Data[payload+dhcpOptsOff:])
	if !opts.hasServerID || (opts.msgType != 2 && opts.msgType != 5) { // OFFER or ACK only
		return
	}
	mac, macOK := srcMAC(f.Data)
	if d.selfMACSet && macOK && mac == d.selfMAC {
		return // that's us - our own OFFER/ACK, identified by the physical NIC MAC
	}
	srv := d.servers[opts.serverID]
	if srv == nil {
		srv = &rogueServer{pres: newPresence(0, d.absence), ip: ipString(opts.serverID)}
		d.servers[opts.serverID] = srv
	}
	if macOK {
		srv.mac = macString(mac)
	}
	srv.pres.sighting(now)
}

// dhcpOpts holds the DHCP options the detectors care about.
type dhcpOpts struct {
	msgType        byte    // option 53
	serverID       [4]byte // option 54
	hasServerID    bool
	requestedIP    [4]byte // option 50 (carried in a DECLINE = the conflicted address)
	hasRequestedIP bool
}

// parseDHCPOptions walks the DHCP option block (after the 4-byte magic cookie),
// pulling message type (53), server identifier (54), and requested IP (50).
func parseDHCPOptions(opts []byte) dhcpOpts {
	var out dhcpOpts
	i := 0
	for i < len(opts) {
		code := opts[i]
		if code == 255 { // end
			break
		}
		if code == 0 { // pad
			i++
			continue
		}
		if i+2 > len(opts) {
			break
		}
		length := int(opts[i+1])
		if i+2+length > len(opts) {
			break
		}
		val := opts[i+2 : i+2+length]
		switch code {
		case 53:
			if length >= 1 {
				out.msgType = val[0]
			}
		case 54:
			if length >= 4 {
				copy(out.serverID[:], val[:4])
				out.hasServerID = true
			}
		case 50:
			if length >= 4 {
				copy(out.requestedIP[:], val[:4])
				out.hasRequestedIP = true
			}
		}
		i += 2 + length
	}
	return out
}

func (d *rogueDHCPDetector) Tick(now time.Time) []Event {
	var events []Event
	for ip, srv := range d.servers {
		switch srv.pres.transition(now) {
		case 1:
			srv.present = true
			events = append(events, Event{
				Action:   "Rogue DHCP server detected",
				Target:   srv.ip + " (" + srv.mac + ")",
				Before:   "none",
				After:    "on " + d.iface,
				Severity: SevError,
			})
		case -1:
			srv.present = false
			events = append(events, Event{
				Action:   "Rogue DHCP server gone",
				Target:   srv.ip + " (" + srv.mac + ")",
				Before:   "rogue",
				After:    "none",
				Severity: SevInfo,
			})
			delete(d.servers, ip)
		}
	}
	// Stable event order so audit rows and tests are deterministic across the map.
	sort.Slice(events, func(i, j int) bool { return events[i].After < events[j].After })
	return events
}

func (d *rogueDHCPDetector) Snapshot() DetectorSnapshot {
	var active []*rogueServer
	for _, srv := range d.servers {
		if srv.present {
			active = append(active, srv)
		}
	}
	s := DetectorSnapshot{Kind: "rogue_dhcp", Subject: d.iface}
	if !d.selfMACSet {
		// Cannot self-verify (own NIC MAC unread): report Unverified, never a
		// confident all-clear, since emission is suppressed and nothing is observed.
		s.Severity = SevInfo
		s.Text = "Rogue DHCP watch unverified (interface MAC unknown)"
		return s
	}
	if len(active) == 0 {
		s.Severity = SevOK
		s.Text = "No rogue DHCP servers"
		return s
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ip < active[j].ip })
	first := active[0]
	s.Severity = SevError
	s.Subject = first.ip
	s.Text = "Rogue DHCP server " + first.ip
	if len(active) > 1 {
		s.Text = itoa(len(active)) + " rogue DHCP servers"
	}
	// sustained is set once ANY currently-present rogue has been seen for a sustained
	// run (not a single warm-held frame): the web layer gates the loud stand-down banner
	// on it, while the row above is already immediate.
	sustained := "0"
	for _, srv := range active {
		if srv.pres.sustainedFor(rogueSustainedAfter) {
			sustained = "1"
			break
		}
	}
	// count lets the web banner report the honest total when several servers answer on
	// one interface - Fields names only the first, so the number would otherwise be lost.
	s.Fields = map[string]string{"server": first.ip, "mac": first.mac, "oui": ouiOf(first.mac), "count": itoa(len(active)), "sustained": sustained}
	return s
}

// ouiOf returns the OUI (first three octets) of a colon-MAC string, "" if short.
func ouiOf(mac string) string {
	if len(mac) >= 8 {
		return mac[:8]
	}
	return ""
}
