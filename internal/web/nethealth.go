package web

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ggo-kea-dhcp/internal/arpscan"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/netmon"
	"ggo-kea-dhcp/internal/web/views"
)

// leaseCacheTTL caps how long the shared lease-IP closure (s.leaseIPs, used by both
// the ARP prober and the Green-GO scanner) reuses one GetLeases result. Each runs a
// ~10s cycle; a TTL just under that interval collapses the near-simultaneous calls
// into a single Kea round-trip per cycle while still refreshing the lease set every
// cycle.
const leaseCacheTTL = 8 * time.Second

// atoiDefault parses s as an int, returning def for an empty or malformed value
// (used for optional detector Fields like clockClass that may be absent).
func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// presenceByIP returns the set of lease IPs (dotted-decimal) the active ARP prober has
// reached within its window, plus whether probing is available. Unavailable (dev sandbox
// / no CAP_NET_RAW) means callers leave presence unknown rather than flagging every device
// offline. Presence is keyed by IP, not MAC: it answers "is the device that holds this
// address reachable now?", so a device at its pinned IP shows online while an unused
// reservation IP for the same MAC does not - no per-MAC ambiguity to special-case.
func (s *Server) presenceByIP() (reachable map[string]bool, available bool) {
	if s.arp == nil {
		return map[string]bool{}, false
	}
	snap := s.arp.Snapshot()
	if snap.ReachableIPs == nil {
		snap.ReachableIPs = map[string]bool{}
	}
	return snap.ReachableIPs, snap.Available
}

// markLeasePresenceWith sets each lease row's Presence ("online"/"offline") from an
// already-collected ARP presence set, keyed by the row's IP, so a dashboard build that
// needs presence in several places (recent leases, the lease table) shares one prober
// snapshot. A no-op when probing is unavailable, leaving Presence "" so the UI shows no
// (misleading) indicator.
func (s *Server) markLeasePresenceWith(reachable map[string]bool, available bool, rows []views.LeaseRow) {
	if !available {
		return
	}
	for i := range rows {
		if reachable[rows[i].IPAddress] {
			rows[i].Presence = "online"
		} else {
			rows[i].Presence = "offline"
		}
	}
}

// normalizeMAC lowercases and strips separators so MACs from Kea leases and from
// netmon frames compare regardless of formatting.
func normalizeMAC(mac string) string {
	return strings.ToLower(strings.ReplaceAll(mac, ":", ""))
}

// startNetmon (re)starts the passive monitor for the active profile's served
// interfaces. It is best-effort: MonitorManager.Start launches goroutines and
// returns immediately, is panic-safe, and never returns an error - so it can
// never abort reconcileActive (the core apply path). Only ever called from
// reconcileActive (the ACTIVE path), at the END - after the interfaces have been
// SetInterfaceStatic'd - so interfaceIPv4s reads the freshly-applied addresses
// rather than racing bring-up; every other reconcile path stops it.
func (s *Server) startNetmon(scopes []ScopeConfig) {
	if s.netmon == nil {
		return
	}
	s.netmon.Start(s.buildNetmonSpecs(scopes))
}

// startArpProber (re)starts the active device-presence prober for the served interfaces.
// Like startNetmon it runs ACTIVE-only and is best-effort (an interface whose socket
// won't open is skipped, never fatal), and is called from reconcileActive after the
// interfaces are up so interfaceIPv4s reads the freshly-applied addresses.
func (s *Server) startArpProber(scopes []ScopeConfig) {
	if s.arp == nil {
		return
	}
	s.arp.Start(s.buildArpSpecs(scopes))
}

// buildArpSpecs derives one ARP-probe spec per served interface: the appliance's own
// IPv4 + MAC on it (the ARP sender) and a closure yielding the current active-lease IPs
// to probe. Reuses the interface/address derivation from buildNetmonSpecs (wlan0 is never
// served, so it is excluded by construction). An interface with no MAC (down / dev
// sandbox) is skipped - the prober simply reports that scope unavailable.
// memoizeLeaseIPs wraps fetch so calls within ttl reuse the last successful result, and a
// failed fetch (ok=false) reuses the last-known set rather than dropping every presence
// dot. It collapses the consumers' same-cycle calls into one underlying GetLeases. now is
// injectable so the TTL behaviour is testable without sleeps.
//
// fetch (an HTTP GetLeases) runs WITHOUT the lock held, using stale-while-revalidate +
// single-flight: when the cache is stale, the first caller marks a refresh in-flight,
// releases the lock, and fetches; a concurrent caller sees the in-flight flag (or fresh
// cache) and returns the last value immediately instead of blocking on the round-trip. So
// the refreshing goroutine waits for its own fetch, but the other consumer never does, and
// there is still at most one fetch in flight.
func memoizeLeaseIPs(fetch func() ([]string, bool), ttl time.Duration, now func() time.Time) func() []string {
	var (
		mu       sync.Mutex
		cached   []string
		fetched  time.Time
		has      bool
		fetching bool
	)
	return func() []string {
		mu.Lock()
		fresh := has && now().Sub(fetched) < ttl
		if fresh || fetching {
			v := cached // fresh, or a refresh is already running: don't block on the fetch
			mu.Unlock()
			return v
		}
		fetching = true
		mu.Unlock()

		v, ok := fetch() // unlocked: a concurrent caller returns cached, never blocks here

		mu.Lock()
		fetching = false
		if ok {
			cached, fetched, has = v, now(), true
		}
		v = cached // on failure keep (and return) the last-known set
		mu.Unlock()
		return v
	}
}

func (s *Server) buildArpSpecs(scopes []ScopeConfig) []arpscan.Spec {
	// The server-level shared, TTL-memoized lease-IP provider (also used by the
	// Green-GO scanner), so N served interfaces probing in the same ~10s cycle trigger
	// a single GetLeases instead of one per interface. It is the global active-lease
	// set; the prober probes by IP, so every interface can use the same list (a lease
	// IP on the wrong segment simply never answers).
	leaseIPs := s.leaseIPs
	seen := map[string]bool{}
	var specs []arpscan.Spec
	for _, sc := range scopes {
		_, ipnet, err := net.ParseCIDR(sc.CIDR)
		if err != nil {
			continue
		}
		iface := "eth0"
		if sc.VlanID != 0 {
			iface = fmt.Sprintf("eth0.%d", sc.VlanID)
		}
		if seen[iface] {
			continue // one socket per interface even if several scopes share it
		}
		seen[iface] = true
		mac, ok := ifaceMAC(iface)
		if !ok {
			continue
		}
		// Sender IP: the live interface address (operator-configurable), falling back to
		// the conventional .1 the reconciler assigns when the address isn't up yet.
		var srcIP [4]byte
		if ips := interfaceIPv4s(iface); len(ips) > 0 {
			srcIP = ips[0]
		} else if ip4 := kea.IncIP(ipnet.IP, 1).To4(); ip4 != nil {
			copy(srcIP[:], ip4)
		}
		specs = append(specs, arpscan.Spec{Iface: iface, SrcIP: srcIP, SrcMAC: mac, LeaseIPs: leaseIPs})
	}
	return specs
}

// ifaceMAC returns the interface's 6-byte hardware address (false if absent / down).
func ifaceMAC(iface string) ([6]byte, bool) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return [6]byte{}, false
	}
	var mac [6]byte
	copy(mac[:], ifi.HardwareAddr)
	return mac, true
}

// buildNetmonSpecs derives one monitor spec per served scope. Specs come only
// from served scopes (eth0 / eth0.<vid>), so the wlan0 uplink is excluded by
// construction (Start also hard-rejects it defensively). The lease-snapshot
// closure keeps netmon free of any kea import.
func (s *Server) buildNetmonSpecs(scopes []ScopeConfig) []netmon.Spec {
	// The full set of configured VIDs - the VLAN-reality detector treats anything
	// else seen on the trunk as unexpected.
	var configuredVIDs []int
	for _, sc := range scopes {
		if sc.VlanID != 0 {
			configuredVIDs = append(configuredVIDs, sc.VlanID)
		}
	}

	leaseFn := func() []netmon.LeasedAddr {
		leases, err := s.kea.GetLeases(1000)
		if err != nil {
			return nil
		}
		out := make([]netmon.LeasedAddr, 0, len(leases))
		for _, l := range leases {
			out = append(out, netmon.LeasedAddr{IP: l.IPAddress})
		}
		return out
	}

	specs := make([]netmon.Spec, 0, len(scopes))
	for _, sc := range scopes {
		_, ipnet, err := net.ParseCIDR(sc.CIDR)
		if err != nil {
			continue
		}
		iface := "eth0"
		if sc.VlanID != 0 {
			iface = fmt.Sprintf("eth0.%d", sc.VlanID)
		}
		// Source the served address from the live interface - the operator can
		// configure it, so we must not assume .1. The same value drives rogue-DHCP
		// self-suppression (our Kea server-identifier) and static-in-pool infra
		// exclusion; getting it wrong would flag our own server as rogue. Fall back
		// to the conventional .1 (what the reconciler assigns by default) only when
		// the address isn't up yet.
		ifaceIPs := interfaceIPv4s(iface)
		if len(ifaceIPs) == 0 {
			var dot1 [4]byte
			if ip4 := kea.IncIP(ipnet.IP, 1).To4(); ip4 != nil {
				copy(dot1[:], ip4)
				ifaceIPs = [][4]byte{dot1}
			}
		}
		// Dynamic pool ranges for this scope (the static-in-pool detector's "inside
		// a pool" test). poolDataForScope yields only DHCP pools, not the static
		// reserve - so a static device legitimately in the reserve is never flagged.
		var pools []netmon.PoolRange
		for _, row := range poolDataForScope(sc, nil) {
			if r, ok := netmon.ParsePoolRange(row.IPRange); ok {
				pools = append(pools, r)
			}
		}
		specs = append(specs, netmon.Spec{
			Iface:          iface,
			MulticastSniff: sc.MulticastSniff,
			Greengo:        sc.Preset == "greengo",
			InterfaceIPs:   ifaceIPs,
			Pools:          pools,
			ConfiguredVIDs: configuredVIDs,
			Leases:         leaseFn,
			LeaseLifetime:  s.leaseLifetime(),
			// VLAN-reality runs only on the raw eth0 monitor (the untagged scope) -
			// an eth0.<vid> socket sees tag-stripped frames. A pure-trunk profile has
			// no untagged scope, so a dedicated raw-eth0 monitor is synthesized below.
			WatchVLANs: sc.VlanID == 0,
		})
	}

	// Pure-trunk profile (every scope tagged): synthesize a raw eth0 monitor that
	// runs ONLY VLAN-reality, so the detector isn't silently absent on the normal
	// all-tagged Green-GO deployment.
	if len(configuredVIDs) > 0 && !hasUntaggedScope(scopes) {
		specs = append(specs, netmon.Spec{
			Iface:          "eth0",
			ConfiguredVIDs: configuredVIDs,
			RawTrunkOnly:   true,
		})
	}
	return specs
}

// applyScopeNames sets each Network Health sub-card's friendly scope name by
// matching its interface to the active scopes (eth0 / eth0.<vid>). An interface
// with no scope (the synthesized raw-eth0 trunk monitor) is left name-less.
func applyScopeNames(ifaces []views.NetHealthIface, scopes []ScopeConfig) {
	names := map[string]string{}
	for _, sc := range scopes {
		if sc.Name == "" {
			continue
		}
		iface := "eth0"
		if sc.VlanID != 0 {
			iface = fmt.Sprintf("eth0.%d", sc.VlanID)
		}
		names[iface] = sc.Name
	}
	for i := range ifaces {
		ifaces[i].ScopeName = names[ifaces[i].Iface]
	}
}

// hasUntaggedScope reports whether any scope is served untagged on eth0 (so a raw
// eth0 monitor already exists and carries the VLAN detector).
func hasUntaggedScope(scopes []ScopeConfig) bool {
	for _, sc := range scopes {
		if sc.VlanID == 0 {
			return true
		}
	}
	return false
}

// interfaceIPv4s returns the live IPv4 addresses bound to iface (empty if the
// interface is down / absent, e.g. in the dev sandbox before bring-up).
func interfaceIPv4s(iface string) [][4]byte {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out [][4]byte
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipn.IP.To4(); v4 != nil {
			var b [4]byte
			copy(b[:], v4)
			out = append(out, b)
		}
	}
	return out
}

// netSignals bundles everything derived from a single netmon SnapshotAll pass:
// the per-interface health card plus the cross-cutting LLDP "you are here" chip,
// the high-severity alert strip, and the PTP clock panel. One pass = one lock.
type netSignals struct {
	Health views.NetHealthView
	LLDP   views.LLDPChip
	PTP    []views.PTPRow
}

// netSnapshotData bundles a dashboard build's network-derived inputs: the netmon
// signals (Network Health / alerts / PTP) from one SnapshotAll pass, plus the device
// presence set (Live = lease IPs the ARP prober has reached, Available = whether
// probing is up). Two sources, one struct, so a build reads each once.
type netSnapshotData struct {
	Signals netSignals
	// Live is the set of lease IPs (dotted-decimal) currently reachable per the active
	// ARP prober - keyed by IP, since presence is "the device at this address answered".
	Live      map[string]bool
	Available bool
	// GgoNames is the scanned Green-GO device names keyed by normalized MAC, derived
	// from the SAME ggoscan snapshot as the firmware rows so a dashboard build takes
	// one scanner snapshot, not one per consumer (firmware rows + lease-name overlay).
	GgoNames map[string]string
}

// buildNetSignals reads the monitor's per-interface snapshots once and maps them
// to the dashboard's netmon-derived views. Standalone helper for callers that need
// only the signals; a full dashboard build uses collectNetSnapshot to also get
// liveness from the same pass.
func (s *Server) buildNetSignals() netSignals {
	var sig netSignals
	if s.netmon == nil {
		return sig
	}
	for _, snap := range s.netmon.SnapshotAll() {
		s.addInterfaceSnapshot(&sig, snap)
	}
	if s.ggoscan != nil {
		sig.Health.Firmware = buildFirmwareRows(s.ggoscan.Snapshot())
	}
	return sig
}

// statusPillView aggregates the lifecycle state with the live network-health signals
// (the same per-interface detector warn/err counts the Network Health card rollup
// shows, plus firmware mismatches) into the header status-pill view. The Details are
// the alert titles, shown in the pill's tooltip. Backend service health (Kea/MariaDB/
// uplink) is deliberately NOT folded in here - it gets the more prominent
// #backend-alert strip above the page h1 (see views.BackendAlert / health.go).
func (s *Server) statusPillView(state string, nh views.NetHealthView) views.StatusPillView {
	v := views.StatusPillView{State: state}
	for _, ifc := range nh.Interfaces {
		v.WarnCount += ifc.WarnCount
		v.ErrCount += ifc.ErrCount
		// Prefix each detail with the scope/interface it came from, so the tooltip
		// disambiguates otherwise-identical warnings ("No traffic" on four VLANs).
		label := ifc.ScopeName
		if label == "" {
			label = ifc.Iface
		}
		for _, r := range ifc.Rows {
			if r.Severity == "warn" || r.Severity == "error" {
				v.Details = append(v.Details, label+": "+r.Title)
			}
		}
	}
	for _, fw := range nh.Firmware { // mixed firmware is a warning
		v.WarnCount++
		v.Details = append(v.Details, fw.Summary)
	}
	return v
}

// buildStatusPill is statusPillView with a fresh netmon snapshot, for callers without a
// precomputed dashboard view (a page render, a backend-health change).
func (s *Server) buildStatusPill(state string) views.StatusPillView {
	return s.statusPillView(state, s.buildNetSignals().Health)
}

// collectNetSnapshot reads the netmon snapshots ONCE for the dashboard signals (Network
// Health card, alert strip, PTP) and the ARP prober ONCE for device presence, so a full
// dashboard build pays a single read of each rather than re-reading per consumer.
func (s *Server) collectNetSnapshot() netSnapshotData {
	ns := netSnapshotData{Live: map[string]bool{}}
	if s.netmon != nil {
		for _, snap := range s.netmon.SnapshotAll() {
			s.addInterfaceSnapshot(&ns.Signals, snap)
		}
	}
	if s.ggoscan != nil {
		snap := s.ggoscan.Snapshot() // one scanner snapshot for both firmware rows + names
		ns.Signals.Health.Firmware = buildFirmwareRows(snap)
		ns.GgoNames = namesFromDevices(snap.Devices)
	}
	ns.Live, ns.Available = s.presenceByIP()
	return ns
}

// addInterfaceSnapshot maps one netmon snapshot into the accumulating signals
// (per-interface health card + the cross-cutting LLDP/alert/PTP signals lifted out
// of the rows). Read-only (netmon is a pure observer): no Kea, no DB. The backend's
// structured signal (kind/severity/subject/text) is carried straight through; the
// templ decides presentation.
func (s *Server) addInterfaceSnapshot(sig *netSignals, snap netmon.Snapshot) {
	degraded := !snap.Available || snap.Level != netmon.LevelFull
	// Note carries the honest reason: the monitor's own note (dev-mode /
	// permanently-degraded) takes precedence; otherwise derive it from the
	// actual governor level, so the card never claims "multicast paused" when
	// it is really counters-only or fully paused.
	note := snap.Note
	if note == "" && degraded {
		note = levelNote(snap.Level)
	}
	ifc := views.NetHealthIface{
		Iface:     snap.Iface,
		Available: snap.Available,
		Note:      note,
		Level:     snap.Level.String(),
		Degraded:  degraded,
		LinkMode:  strings.ToLower(s.net.GetLinkStatus(snap.Iface).LinkState),
	}
	for _, d := range snap.Detectors {
		detail := netHealthDetail(d)
		row := views.NetHealthRow{
			Kind:     d.Kind,
			Severity: string(d.Severity),
			Title:    d.Text,
			Detail:   detail,
		}
		// A newline-separated detail (the device roster) becomes one tooltip row per
		// device; Detail keeps a flat " · " join for the aria-label.
		if strings.Contains(detail, "\n") {
			row.DetailRows = strings.Split(detail, "\n")
			row.Detail = strings.ReplaceAll(detail, "\n", " · ")
		}
		ifc.Rows = append(ifc.Rows, row)
		switch d.Severity {
		case netmon.SevOK:
			ifc.OKCount++
		case netmon.SevWarn:
			ifc.WarnCount++
		case netmon.SevError:
			ifc.ErrCount++
		}
		// Cross-cutting signals lifted out of the per-interface rows.
		switch d.Kind {
		case "lldp":
			if !sig.LLDP.Present && d.Severity == netmon.SevOK {
				if sw := d.Fields["switch"]; sw != "" {
					sig.LLDP = views.LLDPChip{Present: true, Switch: sw, Port: d.Fields["port"], NativeVLAN: d.Fields["native_vlan"]}
				}
			}
		case "ptp":
			// Only a real grandmaster (subject "domain N") promotes the PTP stat
			// tile; the detector's idle "No PTP grandmaster seen" (subject = the
			// interface) is not a GM and must not show a tile.
			if strings.HasPrefix(d.Subject, "domain ") {
				sig.PTP = append(sig.PTP, views.PTPRow{
					Severity:   severityDot(d.Severity),
					Domain:     d.Subject,
					Text:       d.Text,
					ClockClass: atoiDefault(d.Fields["clockClass"], -1),
				})
			}
		}
	}
	// Order detector rows by severity first (errors, warnings, the green "confirmed
	// good", then the gray "informational / not yet observed"), and WITHIN a severity
	// by detector relevance (DHCP integrity → Green-GO → fabric → link), so even an
	// all-clear card reads in a deliberate order rather than detector-registration order.
	sort.SliceStable(ifc.Rows, func(i, j int) bool {
		ri, rj := rowSeverityRank(ifc.Rows[i].Severity), rowSeverityRank(ifc.Rows[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return detectorKindOrder(ifc.Rows[i].Kind) < detectorKindOrder(ifc.Rows[j].Kind)
	})
	sig.Health.Interfaces = append(sig.Health.Interfaces, ifc)
}

// rowSeverityRank orders detector rows by severity: errors, warnings, the green
// "confirmed good" (ok), then the gray "informational / not yet observed" (info /
// unknown) last. Row severity strings are the netmon.Severity values.
func rowSeverityRank(sev string) int {
	switch sev {
	case "error":
		return 0
	case "warn":
		return 1
	case "ok":
		return 2
	default: // "info" and anything neutral - gray, ranked below green
		return 3
	}
}

// detectorKindOrder is the within-severity relevance order: DHCP-integrity detectors
// first (a rogue server / address conflict / pool squatter directly breaks DHCP), then
// the Green-GO device + config census, then the network fabric (VLAN, multicast,
// timing, topology), then link stability. Unknown kinds sort last.
func detectorKindOrder(kind string) int {
	switch kind {
	case "rogue_dhcp":
		return 0
	case "duplicate_ip":
		return 1
	case "static_in_pool":
		return 2
	case "greengo":
		return 3
	case "greengo_config":
		return 4
	case "vlan":
		return 5
	case "igmp":
		return 6
	case "ptp":
		return 7
	case "sacn":
		return 8
	case "lldp":
		return 9
	case "storm":
		return 10
	case "idle":
		return 11
	default:
		return 99
	}
}

// severityDot maps a netmon severity to the dashboard status-dot variant
// (error->err, warn->warn, ok->ok, info/other neutral) - mirrors views.netHealthDot.
func severityDot(sev netmon.Severity) string {
	switch sev {
	case netmon.SevError:
		return "err"
	case netmon.SevWarn:
		return "warn"
	case netmon.SevOK:
		return "ok"
	default:
		return ""
	}
}

// levelNote returns the honest card banner for a degraded-but-available
// interface, matching the actual governor level.
func levelNote(level netmon.Level) string {
	switch level {
	case netmon.LevelNoPromisc:
		return "multicast inspection paused - high load"
	case netmon.LevelCountersOnly:
		return "reduced monitoring - high load (counters only)"
	case netmon.LevelPaused:
		return "monitoring paused - high load"
	default:
		return ""
	}
}

// netHealthDetail builds the optional muted secondary line for a detector row
// from its machine-readable fields, so the card shows the actionable specifics
// (the rogue server's MAC, the squatter's OUI, the switch port) without the
// backend baking in presentation.
func netHealthDetail(d netmon.DetectorSnapshot) string {
	// iface is the monitored interface - but a few detectors override Subject (PTP →
	// "domain N", greengo_config → the config name), so only the detectors below that
	// keep Subject==iface append it.
	iface := d.Subject
	switch d.Kind {
	case "rogue_dhcp":
		if mac := d.Fields["mac"]; mac != "" {
			return "server " + d.Fields["server"] + " · " + mac + " · on " + iface
		}
	case "duplicate_ip":
		if a := d.Fields["address"]; a != "" {
			detail := "address " + a
			if n := d.Fields["declines"]; n != "" && n != "0" {
				detail += " · " + n + " declines"
			}
			return detail + " · on " + iface
		}
	case "static_in_pool":
		// The squatting device's exact IP + MAC + which pool it sits in, and where.
		if ip := d.Fields["ip"]; ip != "" {
			detail := ip + " (" + d.Fields["mac"] + ")"
			if pool := d.Fields["pool"]; pool != "" {
				detail += " · pool " + pool
			}
			return detail + " · on " + iface
		}
	case "lldp":
		// Subject is the switch/port here (the row already shows "Uplink: <switch>/<port>"),
		// not the iface - so don't append it; that just repeated the row. The bubble spells
		// out the neighbour and adds the native VLAN, which the compact row omits.
		if port := d.Fields["port"]; port != "" {
			detail := "switch " + d.Fields["switch"] + " port " + port
			if vid := d.Fields["native_vlan"]; vid != "" {
				detail += " · native VLAN " + vid
			}
			return detail
		}
	case "igmp":
		// Show the querier's source IP as-is. 0.0.0.0 is a valid value (a snooping/proxy
		// querier sources from it) and the operator wants to see it, not have it hidden.
		if q := d.Fields["querier"]; q != "" {
			return "querier " + q + " " + d.Fields["version"] + " · on " + iface
		}
	case "ptp":
		// Subject is "domain N" here, not the interface - don't append iface.
		if cc := d.Fields["clockClass"]; cc != "" {
			return "grandmaster clock class " + cc
		}
	case "vlan":
		// Which tagged VLAN(s), on which trunk interface, and the actionable framing.
		if vids := d.Fields["vids"]; vids != "" {
			return "VID " + vids + " · tagged on " + iface + " · no DHCP scope serves it"
		}
	case "greengo":
		// The detector picks the right bubble per severity (Fields["tip"]): the device
		// roster (family · IP · MAC) on a healthy row, the family census on a warn row.
		return d.Fields["tip"]
	case "greengo_config":
		// Subject is the config name here, not the interface - don't append iface.
		// No config heard yet means empty Fields: emit nothing rather than a bare
		// "config " (which surfaced as a stray "config" tooltip on the none-seen row).
		cfg := d.Fields["config"]
		if cfg == "" {
			return ""
		}
		detail := "config " + cfg
		if g := d.Fields["group"]; g != "" {
			detail += " · multicast group " + g
		}
		return detail
	}
	return ""
}
