package netmon

import (
	"sort"
	"time"
)

// defaultRogueAbsence: a competing server is volatile, but we keep a sighting
// "warm" for a while so a server that offers intermittently still shows as
// present rather than flapping.
const defaultRogueAbsence = 120 * time.Second

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
type rogueDHCPDetector struct {
	iface      string
	selfMAC    [6]byte
	selfMACSet bool
	absence    time.Duration
	servers    map[[4]byte]*rogueServer
}

type rogueServer struct {
	pres    *presence
	ip      string
	mac     string
	present bool
}

func newRogueDHCPDetector(iface string, selfMAC [6]byte, macKnown bool, absence time.Duration) *rogueDHCPDetector {
	if absence <= 0 {
		absence = defaultRogueAbsence
	}
	return &rogueDHCPDetector{
		iface:      iface,
		selfMAC:    selfMAC,
		selfMACSet: macKnown,
		absence:    absence,
		servers:    make(map[[4]byte]*rogueServer),
	}
}

func (d *rogueDHCPDetector) Consume(f Frame, now time.Time) {
	et, off, _, ok := etherInfo(f.Data)
	if !ok || et != etherTypeIPv4 {
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
	s.Fields = map[string]string{"server": first.ip, "mac": first.mac, "oui": ouiOf(first.mac)}
	return s
}

// ouiOf returns the OUI (first three octets) of a colon-MAC string, "" if short.
func ouiOf(mac string) string {
	if len(mac) >= 8 {
		return mac[:8]
	}
	return ""
}
