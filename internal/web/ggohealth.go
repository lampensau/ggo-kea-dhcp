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
	if s.mon.Ggoscan == nil {
		return
	}
	s.mon.Ggoscan.Start(s.buildGgoSpecs(scopes))
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
	s.ggoFw.setScopes(fw)
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
	if s.mon.Ggoscan == nil {
		return nil
	}
	return namesFromDevices(s.mon.Ggoscan.Snapshot().Devices)
}

// ggoDeviceByMAC returns the scanned Green-GO device with the given (any-form) MAC,
// if the scanner currently knows one. The scan inventory is the appliance's proof
// that an address belongs to a Green-GO client, and carries the device's current IP
// and name - the basis for the reboot-to-apply offer.
func (s *Server) ggoDeviceByMAC(mac string) (ggoscan.Device, bool) {
	if s.mon.Ggoscan == nil {
		return ggoscan.Device{}, false
	}
	want := normalizeMAC(mac)
	if want == "" {
		return ggoscan.Device{}, false
	}
	for _, d := range s.mon.Ggoscan.Snapshot().Devices {
		if normalizeMAC(d.MAC) == want {
			return d, true
		}
	}
	return ggoscan.Device{}, false
}

// ggoDeviceByIP returns the scanned Green-GO device answering at ip, if known. Used
// by the release-path reboot offer (rebootOfferForIP) to prefill the dialog; the
// handler itself re-derives eligibility from the live MAC at the address, not this map.
func (s *Server) ggoDeviceByIP(ip string) (ggoscan.Device, bool) {
	if s.mon.Ggoscan == nil || ip == "" {
		return ggoscan.Device{}, false
	}
	for _, d := range s.mon.Ggoscan.Snapshot().Devices {
		if d.IP == ip {
			return d, true
		}
	}
	return ggoscan.Device{}, false
}

// rebootOfferForMAC returns the reboot-to-apply flash context for a device just moved
// to a new address by a reserve or re-pin, or ok=false when no offer applies. It only
// offers when the device is a known Green-GO client (in the scan inventory) AND is
// answering ARP right now, so the reboot targets a device that is actually reachable.
// The offered IP is the device's current address (where it answers), not the new one:
// the reboot has to reach it where it is so it re-requests DHCP and adopts the change.
func (s *Server) rebootOfferForMAC(mac string) (FlashDevice, bool) {
	dev, ok := s.ggoDeviceByMAC(mac)
	if !ok || dev.IP == "" {
		return FlashDevice{}, false
	}
	if reachable, available := s.presenceByIP(); !available || !reachable[dev.IP] {
		return FlashDevice{}, false
	}
	return FlashDevice{MAC: dev.MAC, IP: dev.IP, Name: rebootDeviceName(dev)}, true
}

// rebootOfferForIP is rebootOfferForMAC keyed by the current address instead of the
// MAC (the lease-release path knows the IP the device is on). Same eligibility: a
// known Green-GO client, answering ARP now.
func (s *Server) rebootOfferForIP(ip string) (FlashDevice, bool) {
	dev, ok := s.ggoDeviceByIP(ip)
	if !ok {
		return FlashDevice{}, false
	}
	if reachable, available := s.presenceByIP(); !available || !reachable[ip] {
		return FlashDevice{}, false
	}
	return FlashDevice{MAC: dev.MAC, IP: ip, Name: rebootDeviceName(dev)}, true
}

// rebootDeviceName is the display label for a reboot offer: the device's scanned name
// run through the shared hostname sanitizer (never a second, separate sanitize), or
// its MAC when the scan carried no usable name.
func rebootDeviceName(dev ggoscan.Device) string {
	if n := slugifyHostname(dev.Name); n != "" {
		return n
	}
	return dev.MAC
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
				rows[i].HostnameDerived = true // filled from the scan, not device-reported
			}
		}
	}
}

// slugifyHostname converts a device name to a DNS-safe label: lowercase, alnum and
// single dashes, trimmed, capped at the 63-char DNS label limit. Returns "" when
// nothing usable remains. The single sanitizer behind every stored reservation/pin
// hostname and, via HostnameSlugs, every displayed device name.
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
// Network Health sub-cards it belongs to (the fleet can span scopes).
type fwFinding struct {
	ifaces []string
	row    views.NetHealthRow
}

// firmwareFindings turns the scan inventory into at most ONE Network Health
// detector row (kind "firmware", severity warn): the fleet-wide release check
// (ggoscan.ReleaseMismatch - one release across all device types, legacy
// exemption included), with a capped per-device roster for the info-tip. The
// finding is attributed to every greengo scope holding one of the divergent
// devices; when none matches a scope (link-local squatters) it falls back to
// the first scanned scope, so it is never silently dropped.
func firmwareFindings(devices []ggoscan.Device, scopes []fwScope) []fwFinding {
	sp := ggoscan.ReleaseMismatch(devices)
	if sp == nil || len(scopes) == 0 {
		return nil
	}
	parts := make([]string, 0, len(sp.Releases))
	for _, r := range sp.Releases {
		parts = append(parts, strconv.Itoa(r.N)+" on "+r.Release)
	}
	row := views.NetHealthRow{
		Kind:     "firmware",
		Severity: "warn",
		Title:    "Mixed firmware: " + strings.Join(parts, ", "),
	}
	for i, d := range sp.Devices {
		if i >= firmwareTipCap {
			row.DetailRows = append(row.DetailRows, "+"+strconv.Itoa(len(sp.Devices)-firmwareTipCap)+" more")
			break
		}
		name := d.Name
		if name == "" {
			name = d.MAC
		}
		row.DetailRows = append(row.DetailRows, name+" · "+d.IP+" · "+d.Version)
	}
	row.Detail = strings.Join(row.DetailRows, " · ")
	return []fwFinding{{ifaces: fwIfacesFor(sp.Devices, scopes), row: row}}
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
	scopes := s.ggoFw.snapshotScopes()
	findings := firmwareFindings(snap.Devices, scopes)
	s.auditFirmwareTransition(findings)
	for _, f := range findings {
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

// auditFirmwareTransition records the firmware-mismatch state's edges in the audit
// log. The mismatch was card-only, which broke the status-pill → audit-log trail:
// the pill counted a warning the log never mentioned. Keyed on the row title (the
// release census), so a genuine census change (a device upgraded) re-audits while
// the every-render calls stay silent. attachFirmware runs from concurrent render
// paths; the signature compare-and-set is serialized inside fwCensus.transition.
func (s *Server) auditFirmwareTransition(findings []fwFinding) {
	sig := ""
	if len(findings) > 0 {
		sig = findings[0].row.Title
	}
	prev, changed := s.ggoFw.transition(sig)
	if !changed {
		return
	}
	if sig != "" {
		// After carries the per-device roster (name · IP · version, tip-capped) so the
		// audit entry names the involved clients, not just the release census.
		roster := strings.Join(findings[0].row.DetailRows, ", ")
		_ = s.sqlite.LogAudit("SYSTEM", "Mixed Green-GO firmware", strings.TrimPrefix(sig, "Mixed firmware: "), "uniform", roster, "WARNING")
	} else if prev != "" {
		_ = s.sqlite.LogAudit("SYSTEM", "Green-GO firmware mismatch cleared", strings.TrimPrefix(prev, "Mixed firmware: "), "mixed", "uniform", "INFO")
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
