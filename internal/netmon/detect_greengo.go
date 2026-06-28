package netmon

import (
	"sort"
	"strings"
	"time"
)

// isEvenutionMAC reports whether a MAC is in the IEEE vendor block 00:1f:80. That
// block belongs to the vendor Evenution, whose brands include BOTH ELC (lighting)
// and Green-GO (intercom) - so the OUI alone proves only "Evenution device", NOT
// Green-GO. We classify the device family from the MAC suffix (the known Green-GO
// product ranges); a suffix outside a known Green-GO block stays "unclassified".
// Definitive Green-GO confirmation only comes from G5/G-G traffic, not this passive
// ARP view. Checked on raw bytes (no string alloc) since most ARP frames fail it.
func isEvenutionMAC(mac [6]byte) bool {
	return mac[0] == 0x00 && mac[1] == 0x1f && mac[2] == 0x80
}

// ggoFamilyByBase maps the 0x1000-aligned MAC-suffix block (suffix = MAC[3:6]) to
// the Green-GO product family, per the vendor's allocation. The MAC cannot resolve
// the exact model inside a shared block (e.g. RDX/SI/Beacon all live in 0x217000),
// so these are family labels, not exact models. Beltpack X is contiguous across
// 0x200000-0x204000.
var ggoFamilyByBase = map[uint32]string{
	0x200000: "BPX",
	0x201000: "BPX",
	0x202000: "BPX",
	0x203000: "BPX",
	0x204000: "BPX",
	0x210000: "MCD/MCR",
	0x211000: "Interface X/Q4WR",
	0x212000: "SW5",
	0x213000: "WP(X)",
	0x214000: "Bridge X/Dante X",
	0x216000: "WAA",
	0x217000: "RDX/SI/Beacon",
	0x220000: "MCX(D)/EXT",
	0x221000: "SW18GBX",
	0x223000: "WAA",
	0x224000: "RDX/SI/Beacon",
	0x225000: "MCX(D)",
	0x226000: "Beacon",
	0x230000: "Stride Antenna",
	0x240000: "SW6",
}

// ggoFamily returns the Green-GO product family for an Evenution MAC, or "" when the
// suffix is outside a known Green-GO block (an ELC / other-Evenution / unmapped
// device). suffix = MAC[3:6]; base = the 0x1000 block.
func ggoFamily(mac [6]byte) string {
	suffix := uint32(mac[3])<<16 | uint32(mac[4])<<8 | uint32(mac[5])
	return ggoFamilyByBase[suffix&0xfff000]
}

// isLinkLocal reports whether ip is in 169.254.0.0/16 - the address a Green-GO
// device claims when DHCP did not answer. For an Evenution device this is a direct
// indictment of the appliance's own DHCP reachability.
func isLinkLocal(ip uint32) bool { return ip&0xffff0000 == 0xa9fe0000 }

// greengoDetector is the passive Green-GO census. It watches ARP (the same
// broadcast frames static-in-pool already sees - no extra capture), tracks the
// Evenution (00:1f:80) devices live on the wire, classifies each by MAC-suffix
// family, and surfaces two DHCP-relevant warnings:
//
//   - link-local: an Evenution device sourcing 169.254/16 means DHCP isn't
//     reaching it (audited, one event per device edge).
//   - no-lease: an Evenution device active with no Kea lease and not link-local
//     (static IP or wrong subnet) - a card-severity bump only, since static-in-pool
//     already audits in-pool squatters.
//
// Detect-and-warn only; never mutates Kea. Reuses the static-in-pool warm-up +
// lease-snapshot machinery to avoid onboarding false positives.
type greengoDetector struct {
	iface        string
	servedVID    int // this monitor's served VLAN (0 = untagged eth0)
	leases       LeaseSnapshotFunc
	absence      time.Duration
	leaseRefresh time.Duration
	warmup       time.Duration

	startedAt   time.Time
	lastRefresh time.Time
	leasedSet   map[uint32]bool
	haveLeases  bool
	warming     bool // last Tick's warm-up state, read by Snapshot

	devices map[string]*ggoDevice // keyed by MAC string
}

type ggoDevice struct {
	pres      *presence
	mac       string
	ip        uint32
	ipStr     string
	vlan      int    // the VLAN this device was last seen on (0 = untagged)
	family    string // "" = unclassified (Evenution but not a known Green-GO block)
	present   bool
	linkLocal bool
	flagged   bool // currently flagged as link-local (event-edge state, warm-up-gated)
}

func newGreengoDetector(iface string, leases LeaseSnapshotFunc, absence time.Duration, servedVID int) *greengoDetector {
	if absence <= 0 {
		absence = defaultSquatterAbsence
	}
	return &greengoDetector{
		iface:        iface,
		servedVID:    servedVID,
		leases:       leases,
		absence:      absence,
		leaseRefresh: defaultLeaseRefresh,
		warmup:       staticWarmup,
		devices:      make(map[string]*ggoDevice),
	}
}

// Consume tracks Evenution devices from BOTH their ARP frames AND their UDP-5810 'h'
// broadcast (every ~5s). ARP is sporadic - a link-local device may barely ARP - so the
// 'h' heartbeat is the reliable presence signal that lets detection survive a restart
// without waiting for the next ARP. Each carries the source MAC + IP + VLAN.
func (d *greengoDetector) Consume(f Frame, now time.Time) {
	et, off, vid, ok := etherInfo(f.Data)
	if !ok {
		return
	}
	vlan := effectiveVID(vid, f)
	switch et {
	case etherTypeARP:
		d.consumeARP(f.Data, off, vlan, now)
	case etherTypeIPv4:
		d.consumeH(f.Data, off, vlan, now)
	}
}

// consumeARP records presence from an Evenution ARP (sender MAC + sender IP).
func (d *greengoDetector) consumeARP(b []byte, off, vlan int, now time.Time) {
	// ARP: htype(2) ptype(2) hlen(1) plen(1) op(2) sha(6) spa(4) tha(6) tpa(4).
	if off+28 > len(b) {
		return
	}
	sha, ok := macAt(b, off+8)
	if !ok || !isEvenutionMAC(sha) { // OUI gate before any string alloc
		return
	}
	var spa [4]byte
	copy(spa[:], b[off+14:off+18])
	if spa == ([4]byte{}) { // ARP probe (sender 0.0.0.0): no claimed address yet
		return
	}
	d.see(sha, ip4ToU32(spa), ipString(spa), vlan, now)
}

// consumeH records presence from an Evenution UDP-5810 'h' broadcast (source MAC + IP).
// The BPF guarantees a 5810 frame on a Green-GO interface is an 'h'; decoding the config
// itself is greengoHDetector's job, so this only needs the headers for presence.
func (d *greengoDetector) consumeH(b []byte, off, vlan int, now time.Time) {
	var sha [6]byte
	copy(sha[:], b[6:12]) // ethernet source MAC
	if !isEvenutionMAC(sha) {
		return
	}
	proto, src, _, l4, ok := ipv4Info(b, off)
	if !ok || proto != ipProtoUDP || src == ([4]byte{}) {
		return
	}
	sport, dport, _, ok := udpPorts(b, l4)
	if !ok || (sport != ggoBusPort && dport != ggoBusPort) {
		return
	}
	d.see(sha, ip4ToU32(src), ipString(src), vlan, now)
}

// see folds one sighting (from ARP or 'h') into the device census.
func (d *greengoDetector) see(sha [6]byte, ip uint32, ipStr string, vlan int, now time.Time) {
	mac := macString(sha)
	dev := d.devices[mac]
	if dev == nil {
		dev = &ggoDevice{pres: newPresence(0, d.absence), mac: mac, family: ggoFamily(sha)}
		d.devices[mac] = dev
	}
	dev.ip = ip
	dev.ipStr = ipStr
	dev.linkLocal = isLinkLocal(ip)
	dev.vlan = vlan
	dev.pres.sighting(now)
}

func (d *greengoDetector) Tick(now time.Time) []Event {
	if d.startedAt.IsZero() {
		d.startedAt = now
	}
	if d.leases != nil && (!d.haveLeases || now.Sub(d.lastRefresh) >= d.leaseRefresh) {
		set := make(map[uint32]bool)
		for _, l := range d.leases() {
			if ip, ok := parseU32(l.IP); ok {
				set[ip] = true
			}
		}
		d.leasedSet = set
		d.haveLeases = true
		d.lastRefresh = now
	}
	d.warming = now.Sub(d.startedAt) < d.warmup

	var events []Event
	macs := make([]string, 0, len(d.devices))
	for m := range d.devices {
		macs = append(macs, m)
	}
	sort.Strings(macs)

	for _, m := range macs {
		dev := d.devices[m]
		switch dev.pres.transition(now) {
		case 1:
			dev.present = true
		case -1:
			dev.present = false
			if dev.flagged {
				events = append(events, d.clearEvent(dev))
				dev.flagged = false
			}
			delete(d.devices, m)
			continue
		}
		// Link-local is the audited DHCP-failure signal; suppressed during warm-up so a
		// device mid-DHCP (or just off the onboarding lease DB) isn't flagged.
		shouldFlag := dev.present && dev.linkLocal && !d.warming
		switch {
		case shouldFlag && !dev.flagged:
			dev.flagged = true
			events = append(events, Event{
				Action:   "Evenution device on link-local (DHCP not reaching it)",
				Target:   dev.ipStr + " (" + dev.mac + ")",
				Before:   "none",
				After:    "link-local",
				Severity: SevWarn,
			})
		case !shouldFlag && dev.flagged:
			dev.flagged = false
			events = append(events, d.clearEvent(dev))
		}
	}
	return events
}

func (d *greengoDetector) clearEvent(dev *ggoDevice) Event {
	return Event{
		Action:   "Evenution device link-local cleared",
		Target:   dev.ipStr + " (" + dev.mac + ")",
		Before:   "link-local",
		After:    "none",
		Severity: SevInfo,
	}
}

func (d *greengoDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "greengo", Subject: d.iface}
	present, linkLocal, noLease, confirmedServed := 0, 0, 0, 0
	families := map[string]int{}
	var foreign []*ggoDevice // present devices seen on a VLAN we do not serve
	var served []*ggoDevice  // present devices on our served VLAN (for the roster tooltip)
	for _, dev := range d.devices {
		if !dev.present {
			continue
		}
		if dev.vlan != d.servedVID {
			// An Evenution device on a VLAN with no scope of ours: it can never get
			// DHCP from us. Report it separately (below) - never fold it into the served
			// census, where it would read as healthy served gear.
			foreign = append(foreign, dev)
			continue
		}
		present++
		served = append(served, dev)
		fam := dev.family
		if fam == "" {
			fam = "unclassified"
		}
		families[fam]++
		if d.haveLeases && !dev.linkLocal && d.leasedSet[dev.ip] {
			// Positively confirmed served (its IP is in the lease set) - true regardless
			// of warm-up, so a freshly-restarted box can show healthy gear green at once.
			confirmedServed++
		}
		switch {
		case dev.flagged: // link-local, warm-up-gated (set in Tick)
			linkLocal++
		case !d.warming && !dev.linkLocal && d.haveLeases && !d.leasedSet[dev.ip]:
			noLease++
		}
	}
	// A Green-GO device on an unserved VLAN is the most actionable signal (it's on the
	// wrong VLAN and can't get DHCP), so it takes precedence over the served census.
	if len(foreign) > 0 {
		return greengoForeignSnapshot(s, foreign)
	}
	if present == 0 {
		// No devices on the wire is neutral/unknown (none seen yet), not a confirmed
		// good state - green only means "devices present AND all served" (below).
		s.Severity = SevInfo
		s.Text = "No Evenution/Green-GO devices seen"
		return s
	}
	// The healthy row is a short count; the device specifics (family/IP/MAC roster, or the
	// family census on a warn row) belong in the info bubble, not the row text.
	summary := itoa(present) + " Evenution/Green-GO " + plural(present, "device", "devices") + " detected"
	census := censusText(present, families)
	s.Fields = map[string]string{"devices": itoa(present), "census": census, "roster": rosterText(served)}
	switch {
	case linkLocal > 0:
		s.Severity = SevWarn
		s.Text = itoa(linkLocal) + " " + plural(linkLocal, "device", "devices") + " on link-local (no DHCP)"
		s.Fields["tip"] = census // the warn row text is short; the bubble lists the family census
		s.Fields["link_local"] = itoa(linkLocal)
		if noLease > 0 {
			s.Fields["no_lease"] = itoa(noLease)
		}
	case noLease > 0:
		s.Severity = SevWarn
		s.Text = itoa(noLease) + " " + plural(noLease, "device", "devices") + " with no DHCP lease"
		s.Fields["tip"] = census
		s.Fields["no_lease"] = itoa(noLease)
	case d.warming && confirmedServed == present:
		// Still warming, but every present device is positively lease-confirmed served -
		// that is unambiguous, so don't make the operator wait out the warm-up on healthy
		// gear (netmon restarts on every profile apply too).
		s.Severity = SevOK
		s.Text = summary
		s.Fields["tip"] = s.Fields["roster"]
	case d.warming:
		// Devices present but at least one isn't yet lease-confirmed (snapshot / link-local
		// flagging are warm-up-gated): neutral, not a premature green.
		s.Severity = SevInfo
		s.Text = summary
		s.Fields["tip"] = s.Fields["roster"]
	default:
		// Present and all served (leased, none link-local) is the healthy state.
		s.Severity = SevOK
		s.Text = summary
		s.Fields["tip"] = s.Fields["roster"]
	}
	return s
}

// greengoForeignSnapshot builds the warning row for Evenution devices seen on a VLAN
// this monitor does not serve: they cannot get DHCP from us, so the actionable framing
// is "move it to a served VLAN, or add a scope for that VLAN". The per-device IP / MAC /
// VLAN breakdown goes to the info bubble.
func greengoForeignSnapshot(s DetectorSnapshot, foreign []*ggoDevice) DetectorSnapshot {
	vids := map[int]bool{}
	for _, dev := range foreign {
		vids[dev.vlan] = true
	}
	vidList := make([]int, 0, len(vids))
	for v := range vids {
		vidList = append(vidList, v)
	}
	sort.Ints(vidList)
	vidStrs := make([]string, len(vidList))
	for i, v := range vidList {
		vidStrs[i] = itoa(v)
	}
	// Per-device detail, sorted by MAC for a stable tooltip.
	sort.Slice(foreign, func(i, j int) bool { return foreign[i].mac < foreign[j].mac })
	parts := make([]string, len(foreign))
	for i, dev := range foreign {
		parts[i] = dev.ipStr + " (" + dev.mac + ") on VLAN " + itoa(dev.vlan)
	}
	s.Severity = SevWarn
	s.Text = itoa(len(foreign)) + " Green-GO " + plural(len(foreign), "device", "devices") +
		" on unserved " + plural(len(vidList), "VLAN", "VLANs") + " " + strings.Join(vidStrs, ", ")
	s.Fields = map[string]string{
		"foreign": itoa(len(foreign)),
		"vids":    strings.Join(vidStrs, ", "),
		"census":  strings.Join(parts, "; "),
	}
	return s
}

// rosterText lists the served devices as "family ip (mac)", one per line (newline
// separated so the UI can give each device its own row), sorted by IP for stable
// output (and a stable change-hash). It is the info-bubble detail for the greengo
// row: the row text is just the count, the bubble names the actual devices. Capped
// at rosterMax so a large fleet stays a hover hint, not a wall - overflow is a final
// "+N more" line.
func rosterText(devs []*ggoDevice) string {
	if len(devs) == 0 {
		return ""
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].ip < devs[j].ip })
	const rosterMax = 6
	parts := make([]string, 0, rosterMax+1)
	for i, dev := range devs {
		if i == rosterMax {
			parts = append(parts, "+"+itoa(len(devs)-rosterMax)+" more")
			break
		}
		fam := dev.family
		if fam == "" {
			fam = "unclassified"
		}
		parts = append(parts, fam+" "+dev.ipStr+" ("+dev.mac+")")
	}
	return strings.Join(parts, "\n")
}

// censusText renders "N Evenution/Green-GO devices: 5 BPX, 2 MCX(D), 1
// unclassified", families ordered by count desc then name.
func censusText(total int, families map[string]int) string {
	type fc struct {
		name string
		n    int
	}
	list := make([]fc, 0, len(families))
	for name, n := range families {
		list = append(list, fc{name, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].name < list[j].name
	})
	parts := make([]string, 0, len(list))
	for _, f := range list {
		parts = append(parts, itoa(f.n)+" "+f.name)
	}
	return itoa(total) + " Evenution/Green-GO " + plural(total, "device", "devices") + ": " + strings.Join(parts, ", ")
}
