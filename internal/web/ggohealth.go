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

// buildGgoSpecs derives one scan spec per Green-GO-preset scope: the scope's
// subnet-directed broadcast (for the periodic sweep) and a shared lease-IP closure
// (for the unicast-on-new-lease path). Non-Green-GO scopes are skipped, so a
// Dante/sACN/generic deployment never scans.
func (s *Server) buildGgoSpecs(scopes []ScopeConfig) []ggoscan.Spec {
	leaseIPs := s.leaseIPs // shared with the ARP prober - one GetLeases per cycle
	seen := map[string]bool{}
	var specs []ggoscan.Spec
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
	}
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

// buildFirmwareRows turns the scan inventory into the Network Health card's
// firmware-mismatch rows: one per model family running mixed firmware, with a
// one-line summary and a capped per-device list for the tooltip.
func buildFirmwareRows(snap ggoscan.Snapshot) []views.FirmwareModelRow {
	groups := ggoscan.FirmwareMismatches(snap.Devices)
	if len(groups) == 0 {
		return nil
	}
	rows := make([]views.FirmwareModelRow, 0, len(groups))
	for _, g := range groups {
		parts := make([]string, 0, len(g.Counts))
		for _, c := range g.Counts {
			parts = append(parts, strconv.Itoa(c.N)+" on "+c.Version)
		}
		row := views.FirmwareModelRow{Summary: g.Model + " - " + strings.Join(parts, ", ")}
		for i, d := range g.Devices {
			if i >= firmwareTipCap {
				row.More = len(g.Devices) - firmwareTipCap
				break
			}
			name := d.Name
			if name == "" {
				name = d.MAC
			}
			row.Devices = append(row.Devices, views.FirmwareDeviceRow{Name: name, IP: d.IP, Version: d.Version})
		}
		rows = append(rows, row)
	}
	return rows
}
