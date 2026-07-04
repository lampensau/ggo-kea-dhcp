package web

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/ggoscan"
	"ggo-kea-dhcp/internal/web/views"
)

// firmwareTipCap bounds the per-device list in a firmware-mismatch tooltip so a
// chaotic fleet can't overflow the viewport; the remainder shows as "+N more".
const firmwareTipCap = 20

// startGgoScan (re)starts the active Green-GO device scan for the served Green-GO
// scopes. Best-effort and ACTIVE-only, like startNetmon/startArpProber; an empty
// spec set (no Green-GO preset scope) stops the scanner.
func (s *Server) startGgoScan(scopes []ScopeConfig) {
	if s.ggoscan == nil {
		return
	}
	s.ggoscan.Start(s.buildGgoSpecs(scopes))
}

// fwScope is one greengo-preset scope the scanner targets: the interface whose
// Network Health sub-card owns any firmware findings, and the subnet used to
// attribute a mismatched device to it.
type fwScope struct {
	iface string
	net   *net.IPNet
}

// buildGgoSpecs derives one scan spec per Green-GO-preset scope: the scope's
// subnet-directed broadcast (for the periodic sweep) and a shared lease-IP closure
// (for the unicast-on-new-lease path). Non-Green-GO scopes are skipped, so a
// Dante/sACN/generic deployment never scans.
func (s *Server) buildGgoSpecs(scopes []ScopeConfig) []ggoscan.Spec {
	leaseIPs := s.leaseIPs // shared with the ARP prober - one GetLeases per cycle
	seen := map[string]bool{}
	var specs []ggoscan.Spec
	var fw []fwScope
	for _, sc := range scopes {
		if sc.Preset != "greengo" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(sc.CIDR)
		if err != nil {
			continue
		}
		bcast, ok := broadcastOf(ipnet)
		if !ok {
			continue
		}
		iface := "eth0"
		if sc.VlanID != 0 {
			iface = fmt.Sprintf("eth0.%d", sc.VlanID)
		}
		if seen[iface] {
			continue
		}
		seen[iface] = true
		specs = append(specs, ggoscan.Spec{Broadcast: bcast, LeaseIPs: leaseIPs})
		fw = append(fw, fwScope{iface: iface, net: ipnet})
	}
	s.ggoFwMu.Lock()
	s.ggoFwScopes = fw
	s.ggoFwMu.Unlock()
	return specs
}

// broadcastOf computes the IPv4 subnet-directed broadcast (network | ^mask) for a
// scope's CIDR.
func broadcastOf(ipnet *net.IPNet) ([4]byte, bool) {
	ip4 := ipnet.IP.To4()
	if ip4 == nil || len(ipnet.Mask) != 4 {
		return [4]byte{}, false
	}
	var b [4]byte
	for i := range 4 {
		b[i] = ip4[i] | ^ipnet.Mask[i]
	}
	return b, true
}

// namesFromDevices keys scanned device names by normalized MAC (skipping unnamed
// devices). Pure helper so a caller that already holds a ggoscan snapshot derives the
// name map without a second Snapshot().
func namesFromDevices(devs []ggoscan.Device) map[string]string {
	if len(devs) == 0 {
		return nil
	}
	m := make(map[string]string, len(devs))
	for _, d := range devs {
		if d.Name != "" {
			m[normalizeMAC(d.MAC)] = d.Name
		}
	}
	return m
}

// ggoNamesByMAC returns the scanned Green-GO device names keyed by normalized MAC.
// Green-GO devices send no DHCP hostname, so this scan-derived name is the only
// friendly label the appliance has for them. Takes its own scanner snapshot - callers
// on the dashboard build path pass the shared map to overlayGgoNamesWith instead.
func (s *Server) ggoNamesByMAC() map[string]string {
	if s.ggoscan == nil {
		return nil
	}
	return namesFromDevices(s.ggoscan.Snapshot().Devices)
}

// overlayGgoNamesWith fills the Hostname of any lease row that lacks one with the
// device's scanned Green-GO name from the given map. Read-only display fill (no
// control-plane write): the device sends no DHCP hostname, so without this its lease
// shows nameless. (A future DDNS-backed reservation write would also publish the name
// to DNS; until then this is the appliance-side label.) A nil names map is a no-op.
func (s *Server) overlayGgoNamesWith(rows []views.LeaseRow, names map[string]string) {
	if names == nil {
		return
	}
	for i := range rows {
		if rows[i].Hostname == "" {
			if n := names[normalizeMAC(rows[i].HWAddress)]; n != "" {
				rows[i].Hostname = n
			}
		}
	}
}

// slugifyHostname converts a device name to a DNS-safe label: lowercase, alnum and
// single dashes, trimmed, capped at the 63-char DNS label limit. Returns "" when
// nothing usable remains. Used to default a manual reservation's hostname to the
// scanned device name so the auto name carries over into operator reservations.
func slugifyHostname(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case r == ' ' || r == '-' || r == '_':
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := b.String()
	if len(out) > 63 {
		out = out[:63]
	}
	return strings.TrimRight(out, "-")
}

// defaultHostnameFor returns the slugified scanned Green-GO name for a MAC, or "" if
// none is known - the default a manual reservation adopts when the operator leaves
// the hostname blank.
func (s *Server) defaultHostnameFor(mac string) string {
	if n := s.ggoNamesByMAC()[normalizeMAC(mac)]; n != "" {
		return slugifyHostname(n)
	}
	return ""
}

// fwFinding is one firmware-mismatch detector row plus the interfaces whose
// Network Health sub-cards it belongs to (a model family can span scopes).
type fwFinding struct {
	ifaces []string
	row    views.NetHealthRow
}

// firmwareFindings turns the scan inventory into per-interface Network Health
// detector rows (kind "firmware", severity warn): one per model family running
// mixed firmware, with a capped per-device roster for the info-tip. Mismatch
// groups are fleet-wide (that is what catches two scopes running mutually
// different but internally uniform versions), so a group is attributed to every
// greengo scope holding one of its devices; a group whose devices match no scope
// (link-local squatters) falls back to the first scanned scope, so a finding is
// never silently dropped.
func firmwareFindings(devices []ggoscan.Device, scopes []fwScope) []fwFinding {
	groups := ggoscan.FirmwareMismatches(devices)
	if len(groups) == 0 || len(scopes) == 0 {
		return nil
	}
	findings := make([]fwFinding, 0, len(groups))
	for _, g := range groups {
		parts := make([]string, 0, len(g.Counts))
		for _, c := range g.Counts {
			parts = append(parts, strconv.Itoa(c.N)+" on "+c.Version)
		}
		row := views.NetHealthRow{
			Kind:     "firmware",
			Severity: "warn",
			Title:    "Mixed firmware: " + g.Model + " - " + strings.Join(parts, ", "),
		}
		for i, d := range g.Devices {
			if i >= firmwareTipCap {
				row.DetailRows = append(row.DetailRows, "+"+strconv.Itoa(len(g.Devices)-firmwareTipCap)+" more")
				break
			}
			name := d.Name
			if name == "" {
				name = d.MAC
			}
			row.DetailRows = append(row.DetailRows, name+" · "+d.IP+" · "+d.Version)
		}
		row.Detail = strings.Join(row.DetailRows, " · ")
		findings = append(findings, fwFinding{ifaces: fwIfacesFor(g.Devices, scopes), row: row})
	}
	return findings
}

// fwIfacesFor attributes a mismatch group to every scanned scope holding one of
// its devices' addresses, in scope order; the first scope is the fallback when
// none matches.
func fwIfacesFor(devices []ggoscan.Device, scopes []fwScope) []string {
	var ifaces []string
	for _, sc := range scopes {
		for _, d := range devices {
			if ip := net.ParseIP(d.IP); ip != nil && sc.net.Contains(ip) {
				ifaces = append(ifaces, sc.iface)
				break
			}
		}
	}
	if len(ifaces) == 0 {
		return []string{scopes[0].iface}
	}
	return ifaces
}

// attachFirmware folds the scan's firmware-mismatch findings into the owning
// interface's Network Health sub-card: appended to its rows, counted in its
// warning rollup, and re-sorted with the other detectors. Only available cards
// render their rows, so a finding whose card is unavailable falls back to the
// first available card - counting a warning on a card that can't show the row
// would leave the rollup claiming more warnings than are visible. With no
// available card at all the finding is dropped (dev mode / capture-less box).
func (s *Server) attachFirmware(h *views.NetHealthView, snap ggoscan.Snapshot) {
	if len(h.Interfaces) == 0 {
		return // nothing to attach to (non-ACTIVE / netmon down) - skip the grouping work
	}
	s.ggoFwMu.Lock()
	scopes := s.ggoFwScopes
	s.ggoFwMu.Unlock()
	for _, f := range firmwareFindings(snap.Devices, scopes) {
		attached := map[*views.NetHealthIface]bool{} // two unavailable ifaces share one fallback card - attach once
		for _, iface := range f.ifaces {
			ifc := availableIface(h, iface)
			if ifc == nil {
				return
			}
			if attached[ifc] {
				continue
			}
			attached[ifc] = true
			ifc.Rows = append(ifc.Rows, f.row)
			ifc.WarnCount++
			sortNetHealthRows(ifc.Rows)
		}
	}
}

// availableIface returns the available interface card named iface, else the
// first available card, else nil.
func availableIface(h *views.NetHealthView, iface string) *views.NetHealthIface {
	var first *views.NetHealthIface
	for i := range h.Interfaces {
		if !h.Interfaces[i].Available {
			continue
		}
		if h.Interfaces[i].Iface == iface {
			return &h.Interfaces[i]
		}
		if first == nil {
			first = &h.Interfaces[i]
		}
	}
	return first
}
