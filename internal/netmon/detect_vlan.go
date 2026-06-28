package netmon

import (
	"sort"
	"time"
)

// vlanDetector compares the 802.1Q VIDs actually seen on the raw trunk against the VIDs the
// active profile configured, surfacing *unexpected* VIDs. It is informational only - seeing
// extra VLANs on a trunk is common and not necessarily wrong - and proposes no config
// change. Needs promiscuous to see frames not destined for us (gated by MulticastSniff via
// the VLAN-reality path). Listens on eth0 only, never wlan0.
//
// A VLAN observed on a trunk is a stable config fact, not a transient, so a seen VID
// LATCHES: it is announced once and stays reported even when its traffic is sparse (a VLAN
// with one quiet talker easily goes minutes between frames - the earlier aging model flapped
// seen/gone, writing an audit row each time). But "latched forever" is wrong too: a single
// stray frame from a momentary miswire would pin the card amber until a profile reapply. So
// the latch SELF-HEALS - a VID re-ages only after a long quiet window (>> any normal trunk
// gap, so a busy VLAN never flaps) and only when tag visibility is confirmed (so absence is
// real, not blindness) - and is dropped immediately when the interface link goes down.
const vlanSelfHeal = 10 * time.Minute

type vlanDetector struct {
	iface      string
	configured map[int]bool
	linkUp     linkStateFunc     // nil => treated as always up (dev sandbox / tests)
	seen       map[int]time.Time // unexpected VID -> last sighting (latched; self-heals after vlanSelfHeal)
	announced  map[int]bool      // VIDs whose one-time "seen" event has already fired
	visible    bool              // a frame carried AUXDATA tag info → tag visibility confirmed
}

func newVLANDetector(iface string, configuredVIDs []int, linkUp linkStateFunc) *vlanDetector {
	cfg := make(map[int]bool, len(configuredVIDs))
	for _, v := range configuredVIDs {
		cfg[v] = true
	}
	return &vlanDetector{
		iface:      iface,
		configured: cfg,
		linkUp:     linkUp,
		seen:       make(map[int]time.Time),
		announced:  make(map[int]bool),
	}
}

func (d *vlanDetector) Consume(f Frame, now time.Time) {
	_, _, vlanID, ok := etherInfo(f.Data)
	if !ok {
		return // untagged, truncated, or double-tagged (etherInfo rejects QinQ)
	}
	if f.VLANKnown {
		// AUXDATA delivered tag info for this frame (even an untagged one) → we can see
		// tags, so a later empty result is a real all-clear, not blindness.
		d.visible = true
		if f.VLAN != 0 {
			vlanID = f.VLAN // tag was offload-stripped from Data; use the recovered VID
		}
	}
	if vlanID == 0 || d.configured[vlanID] {
		return // untagged or an expected VID
	}
	d.seen[vlanID] = now // latch + refresh last-seen (self-heals only after a long quiet window)
}

func (d *vlanDetector) Tick(now time.Time) []Event {
	// Link down: the trunk is gone, so drop every latched VID (the topology may change
	// before it returns). Silent - the link event is the story, not each VID.
	if d.linkUp != nil && !d.linkUp() {
		if len(d.seen) > 0 {
			d.seen = make(map[int]time.Time)
			d.announced = make(map[int]bool)
		}
		return nil
	}
	var events []Event
	for _, v := range d.sortedSeen() {
		// Self-heal a genuinely-removed VLAN: long quiet window AND confirmed visibility.
		if d.visible && now.Sub(d.seen[v]) > vlanSelfHeal {
			delete(d.seen, v)
			delete(d.announced, v)
			events = append(events, Event{
				Action:   "Trunked VLAN no longer seen",
				Target:   "VID " + itoa(v),
				Before:   "seen on " + d.iface + ", no scope",
				After:    "gone",
				Severity: SevInfo,
			})
			continue
		}
		if d.announced[v] {
			continue
		}
		d.announced[v] = true
		// Actionable framing: a tagged VLAN on the trunk that the active profile has no
		// scope for means devices on it get no DHCP from this box. Target names the VLAN
		// (the subject), not the interface, so the audit row reads "... / VID 200".
		events = append(events, Event{
			Action:   "Trunked VLAN has no DHCP scope",
			Target:   "VID " + itoa(v),
			Before:   "none",
			After:    "seen on " + d.iface + ", no scope",
			Severity: SevWarn,
		})
	}
	return events
}

func (d *vlanDetector) sortedSeen() []int {
	vids := make([]int, 0, len(d.seen))
	for v := range d.seen {
		vids = append(vids, v)
	}
	sort.Ints(vids)
	return vids
}

func (d *vlanDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "vlan", Subject: d.iface}
	vids := d.sortedSeen()
	if len(vids) == 0 {
		if d.visible {
			// PACKET_AUXDATA confirmed we can see tags (it recovers the VID the NIC strips
			// via RX-VLAN offload), so an empty result is a genuine all-clear.
			s.Severity = SevOK
			s.Text = "No unexpected VLAN tags"
			return s
		}
		// Never saw AUXDATA tag info (e.g. a kernel that doesn't deliver it while the NIC
		// offloads tags): we may simply be blind. Report neutral "limited" rather than false
		// reassurance.
		s.Severity = SevInfo
		s.Text = "VLAN inspection limited - tags not visible on this NIC"
		return s
	}
	list := ""
	for i, v := range vids {
		if i > 0 {
			list += ", "
		}
		list += itoa(v)
	}
	s.Severity = SevWarn
	s.Text = plural(len(vids), "VLAN", "VLANs") + " " + list + ": no DHCP scope"
	s.Fields = map[string]string{"vids": list}
	return s
}
