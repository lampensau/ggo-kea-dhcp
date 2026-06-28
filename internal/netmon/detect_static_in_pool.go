package netmon

import (
	"sort"
	"strings"
	"time"
)

const (
	// defaultSquatterAbsence: a host is considered gone after this long without an
	// ARP sighting.
	defaultSquatterAbsence = 120 * time.Second
	// defaultLeaseRefresh: how often the slow-tick lease snapshot is refreshed
	// (never per-packet).
	defaultLeaseRefresh = 30 * time.Second
	// staticWarmup suppresses ALL static-in-pool flags for this long after the
	// detector starts. netmon starts at ACTIVE entry - exactly when a client leased by
	// the ONBOARDING Kea (a separate, now-gone lease DB the active snapshot never saw)
	// is still using its old address and has not yet re-DHCP'd into the active profile,
	// so it would otherwise be flagged as static. Comfortably covers the 90s onboarding
	// lease re-DHCP plus the 30s lease-snapshot refresh lag; also covers restarts.
	staticWarmup = 3 * time.Minute
	// staticLeaseGraceFloor / staticLeaseGraceCap bound the per-detector lease-history
	// grace (derived as ~T1 of the active lease, so it auto-scales with the operator's
	// lease setting): long enough to outlast a re-DHCP + refresh lag, capped so a very
	// long lease doesn't suppress a genuine static for days.
	staticLeaseGraceFloor = 2 * time.Minute
	staticLeaseGraceCap   = 60 * time.Minute
)

// LeasedAddr is one Kea lease as netmon sees it. The web layer supplies a closure
// that converts kea.ActiveLease, so netmon imports neither web nor kea.
type LeasedAddr struct {
	IP string
}

// LeaseSnapshotFunc returns the current set of leased addresses. It is called on
// the slow tick only - never per packet - and may be nil (then the detector stays
// quiet, since it cannot prove an address is unleased without the lease set).
type LeaseSnapshotFunc func() []LeasedAddr

// PoolRange is an inclusive IPv4 range [Lo,Hi] for one configured dynamic pool.
type PoolRange struct {
	Lo, Hi uint32
}

func (r PoolRange) contains(ip uint32) bool { return ip >= r.Lo && ip <= r.Hi }

// String renders the range as "lo-hi" for the card detail.
func (r PoolRange) String() string {
	return u32ToIP(r.Lo) + "-" + u32ToIP(r.Hi)
}

// u32ToIP formats a big-endian uint32 as a dotted-quad string.
func u32ToIP(v uint32) string {
	return itoa(int(v>>24&0xff)) + "." + itoa(int(v>>16&0xff)) + "." + itoa(int(v>>8&0xff)) + "." + itoa(int(v&0xff))
}

// ParsePoolRange parses a Kea-style "a.b.c.d-e.f.g.h" pool range.
func ParsePoolRange(s string) (PoolRange, bool) {
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		return PoolRange{}, false
	}
	l, ok1 := parseU32(lo)
	h, ok2 := parseU32(hi)
	if !ok1 || !ok2 || l > h {
		return PoolRange{}, false
	}
	return PoolRange{Lo: l, Hi: h}, true
}

// staticInPoolDetector flags a device using a *static* IP that falls inside a
// configured dynamic pool but has no Kea lease - a squatter that will collide with
// a future DHCP assignment (a DECLINE waiting to happen). It watches ARP passively
// (who-has / gratuitous / reply; broadcast, no promiscuous), maintains the set of
// {IP,MAC} active on the wire, and on the slow tick cross-checks against an
// injected Kea lease snapshot.
//
// Decision (locked): detect & warn ONLY - netmon never mutates Kea. ARP is
// spoofable, so acting on it would let a forged gratuitous ARP carve real pool
// space. The detector's whole value is therefore the *quality* of the warning, so
// the card state is first-class and specific.
type staticInPoolDetector struct {
	iface        string
	pools        []PoolRange
	infra        map[uint32]bool
	leases       LeaseSnapshotFunc
	absence      time.Duration
	leaseRefresh time.Duration
	warmup       time.Duration // suppress all flags this long after startedAt
	leaseGrace   time.Duration // ~T1: a just-de-leased IP isn't a squatter yet

	startedAt    time.Time // first Tick - the warm-up anchor
	lastRefresh  time.Time
	leasedSet    map[uint32]bool
	lastLeasedAt map[uint32]time.Time // IP -> last time seen leased (lease-history grace)
	haveLeases   bool
	hosts        map[uint32]*arpHost
}

type arpHost struct {
	pres      *presence
	ip        uint32
	ipStr     string
	mac       string
	pool      string    // the matched pool range, for the card detail
	firstSeen time.Time // first ARP sighting - gates flagging on a fresh-enough lease view
	present   bool
	flagged   bool
}

func newStaticInPoolDetector(iface string, pools []PoolRange, infraIPs []uint32, leases LeaseSnapshotFunc, absence time.Duration, leaseLifetimeSec int) *staticInPoolDetector {
	if absence <= 0 {
		absence = defaultSquatterAbsence
	}
	grace := time.Duration(leaseLifetimeSec/2) * time.Second // ~T1: a de-leased client re-DHCPs by then
	if grace < staticLeaseGraceFloor {
		grace = staticLeaseGraceFloor
	}
	if grace > staticLeaseGraceCap {
		grace = staticLeaseGraceCap
	}
	infra := make(map[uint32]bool, len(infraIPs))
	for _, ip := range infraIPs {
		infra[ip] = true
	}
	return &staticInPoolDetector{
		iface:        iface,
		pools:        pools,
		infra:        infra,
		leases:       leases,
		absence:      absence,
		leaseRefresh: defaultLeaseRefresh,
		warmup:       staticWarmup,
		leaseGrace:   grace,
		lastLeasedAt: make(map[uint32]time.Time),
		hosts:        make(map[uint32]*arpHost),
	}
}

func (d *staticInPoolDetector) Consume(f Frame, now time.Time) {
	et, off, _, ok := etherInfo(f.Data)
	if !ok || et != etherTypeARP {
		return
	}
	// ARP: htype(2) ptype(2) hlen(1) plen(1) op(2) sha(6) spa(4) tha(6) tpa(4).
	if off+28 > len(f.Data) {
		return
	}
	sha, _ := macAt(f.Data, off+8)
	var spa [4]byte
	copy(spa[:], f.Data[off+14:off+18])
	if spa == ([4]byte{}) { // ARP probe (sender 0.0.0.0): no claimed address yet
		return
	}
	ip := ip4ToU32(spa)
	h := d.hosts[ip]
	if h == nil {
		h = &arpHost{pres: newPresence(0, d.absence), ip: ip, ipStr: ipString(spa), firstSeen: now}
		d.hosts[ip] = h
	}
	h.mac = macString(sha)
	h.pres.sighting(now)
}

func (d *staticInPoolDetector) Tick(now time.Time) []Event {
	if d.startedAt.IsZero() {
		d.startedAt = now // warm-up anchor (first tick after the detector starts)
	}
	// Refresh the lease snapshot on the slow cadence (not per packet), stamping each
	// currently-leased IP's last-seen-leased time for the lease-history grace.
	if d.leases != nil && (!d.haveLeases || now.Sub(d.lastRefresh) >= d.leaseRefresh) {
		set := make(map[uint32]bool)
		for _, l := range d.leases() {
			if ip, ok := parseU32(l.IP); ok {
				set[ip] = true
				d.lastLeasedAt[ip] = now
			}
		}
		d.leasedSet = set
		d.haveLeases = true
		d.lastRefresh = now
		d.pruneLeaseHistory(now)
	}

	// Warm-up: suppress all flags right after the detector starts, so a client that
	// just came off the onboarding lease DB (or a restart) gets a chance to re-DHCP
	// into the active profile before it could be flagged as static.
	warmingUp := now.Sub(d.startedAt) < d.warmup

	var events []Event
	ips := make([]uint32, 0, len(d.hosts))
	for ip := range d.hosts {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i] < ips[j] })

	for _, ip := range ips {
		h := d.hosts[ip]
		switch h.pres.transition(now) {
		case 1:
			h.present = true
		case -1:
			h.present = false
			if h.flagged {
				events = append(events, d.clearEvent(h))
			}
			delete(d.hosts, ip)
			continue
		}
		// Recompute squatter status every tick for present hosts (the lease set
		// changes underneath us - a host that later gets a lease must clear). Suppressed
		// entirely during warm-up.
		pool, squat := "", false
		if h.present && !warmingUp {
			pool, squat = d.squatterPool(h, now)
		}
		switch {
		case squat && !h.flagged:
			h.flagged = true
			h.pool = pool
			// Target is the offending DEVICE (ip + mac), not the interface - the audit log
			// only shows Action + Target, so "...DHCP pool / eth0" told the operator nothing.
			// Static devices are ARP-detected and carry no DHCP hostname, so ip (mac) is the
			// best identity we have; the pool range rides in After for context.
			events = append(events, Event{
				Action:   "Static device in DHCP pool",
				Target:   h.ipStr + " (" + h.mac + ")",
				Before:   "none",
				After:    "pool " + pool,
				Severity: SevWarn,
			})
		case !squat && h.flagged:
			h.flagged = false
			events = append(events, d.clearEvent(h))
		}
	}
	return events
}

func (d *staticInPoolDetector) clearEvent(h *arpHost) Event {
	return Event{
		Action:   "Static device in DHCP pool cleared",
		Target:   h.ipStr + " (" + h.mac + ")",
		Before:   "static",
		After:    "none",
		Severity: SevInfo,
	}
}

// squatterPool reports whether the host is active inside a configured pool, has no
// Kea lease, and is not our infrastructure - returning the matched pool range for the
// card. Requires a lease snapshot - without one we cannot prove "unleased", so we
// never flag.
func (d *staticInPoolDetector) squatterPool(h *arpHost, now time.Time) (string, bool) {
	ip := h.ip
	if !d.haveLeases || d.infra[ip] || d.leasedSet[ip] {
		return "", false
	}
	// Lease-snapshot freshness: never flag on a lease view older than when we first saw
	// the host. A brand-new device gets its lease and ARPs in the gap before the next
	// 30s refresh; without this it flashes "static" for one tick until the snapshot
	// catches up (the 2s flag/clear flap). Wait for a refresh that post-dates the host -
	// that snapshot reflects any lease it now holds.
	if d.lastRefresh.Before(h.firstSeen) {
		return "", false
	}
	// Lease-history grace: an IP leased within ~T1 is a client that just lost or
	// released its lease and has not re-DHCP'd yet - not a static squatter. (The
	// onboarding-reconnect case is handled separately by the warm-up, since that lease
	// lived in a different DB the active snapshot never saw.)
	if t, ok := d.lastLeasedAt[ip]; ok && now.Sub(t) < d.leaseGrace {
		return "", false
	}
	for _, r := range d.pools {
		if r.contains(ip) {
			return r.String(), true
		}
	}
	return "", false
}

// pruneLeaseHistory drops lease-history stamps older than the grace window so the
// map stays bounded by recently-leased pool addresses.
func (d *staticInPoolDetector) pruneLeaseHistory(now time.Time) {
	for ip, t := range d.lastLeasedAt {
		if now.Sub(t) >= d.leaseGrace {
			delete(d.lastLeasedAt, ip)
		}
	}
}

func (d *staticInPoolDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "static_in_pool", Subject: d.iface}
	var flagged []*arpHost
	for _, h := range d.hosts {
		if h.flagged {
			flagged = append(flagged, h)
		}
	}
	if len(flagged) == 0 {
		s.Severity = SevOK
		s.Text = "No static devices in pools"
		return s
	}
	sort.Slice(flagged, func(i, j int) bool { return flagged[i].ip < flagged[j].ip })
	h := flagged[0]
	s.Severity = SevWarn
	s.Subject = h.ipStr
	oui := ouiOf(h.mac)
	// Reworded to give the operator the specific device + remedy and to flag that a
	// deliberately-static device is a benign false-positive here (it only needs a
	// matching reservation so the pool address is never handed to another client).
	s.Text = "Static device " + h.ipStr + " (" + oui + ") is using a DHCP pool address"
	if n := len(flagged) - 1; n > 0 {
		s.Text = h.ipStr + " (" + oui + ") and " + itoa(n) + " more static " + plural(n, "device", "devices") + " using pool addresses - reserve or relocate them (harmless if intentional)"
	}
	s.Fields = map[string]string{
		"ip":     h.ipStr,
		"mac":    h.mac,
		"oui":    oui,
		"pool":   h.pool,
		"reason": "active-not-leased",
	}
	return s
}
