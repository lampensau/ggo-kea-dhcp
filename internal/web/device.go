package web

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// handleDeviceReboot sends a reboot request to the Green-GO device at the posted IP,
// so a just-changed address (a release, a reservation, or a re-pin) takes effect now
// instead of at the device's next DHCP renewal. The reboot is a physical-world side
// effect, so it is always operator-initiated and always audited.
//
// Trust boundary: the posted IP is client state and is never trusted. The handler
// re-derives, from the IP alone, that the address really maps to a currently-reachable
// Green-GO client - it must be in the scan inventory (or hold a current lease/pin whose
// MAC the scanner knows) AND be answering ARP right now. Anything else is refused with
// 403 and audited, so an arbitrary IP can't be turned into a reboot of some other host.
func (s *Server) handleDeviceReboot(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	back := formReturn(r, "/dashboard")
	ip := strings.TrimSpace(r.FormValue("ip"))

	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		s.handleError(w, r, "Enter a valid device address to reboot.", http.StatusBadRequest)
		return
	}

	name, ok := s.rebootEligible(r.Context(), ip)
	if !ok {
		// Not a reachable Green-GO client we manage: refuse and record the attempt.
		_ = s.sqlite.LogAudit(s.getActor(r), "DEVICE_REBOOT", ip, "", "not a reachable Green-GO device", "WARNING")
		s.handleError(w, r, ip+" is not a reachable Green-GO device, so there is nothing to reboot.", http.StatusForbidden)
		return
	}

	if s.ggoscan == nil {
		s.handleError(w, r, "The Green-GO scanner is not running, so the device can't be rebooted right now.", http.StatusServiceUnavailable)
		return
	}
	if err := s.ggoscan.SendReboot(ip); err != nil {
		_ = s.sqlite.LogAudit(s.getActor(r), "DEVICE_REBOOT", name+" -> "+ip, "", err.Error(), "ERROR")
		s.handleError(w, r, "Could not reach "+ip+" to reboot it: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "DEVICE_REBOOT", name+" -> "+ip, "", "", "SUCCESS")
	s.setFlash(w, r, "Rebooting "+name+" - it re-requests DHCP and picks up its new address in a few seconds.", "success")
	s.redirectHTMX(w, r, back)
}

// rebootEligible re-derives, server-side, whether ip is a currently-reachable Green-GO
// client this appliance manages, returning its display name when so. Eligibility needs
// both a Green-GO identity for the address and live ARP presence: the identity comes
// from the scan inventory or, as a fallback, a current lease/pin at that IP whose MAC
// the scanner recognizes; presence comes from the active prober. Never consults the
// posted form beyond the IP.
func (s *Server) rebootEligible(ctx context.Context, ip string) (string, bool) {
	reachable, available := s.presenceByIP()
	if !available || !reachable[ip] {
		return "", false // can't confirm the device is online - don't reboot into the void
	}
	// Primary: the scan inventory maps the address straight to a Green-GO device.
	if dev, ok := s.ggoDeviceByIP(ip); ok {
		return rebootDeviceName(dev), true
	}
	// Fallback: a current lease or pin at the IP whose MAC the scanner knows (covers a
	// device whose lease was just evicted so it no longer answers a scan under this IP).
	if mac := s.macAtIP(ctx, ip); mac != "" {
		if dev, ok := s.ggoDeviceByMAC(mac); ok {
			return rebootDeviceName(dev), true
		}
	}
	return "", false
}

// macAtIP finds the MAC currently at ip from the control plane: an active Kea lease,
// else a pinned port that a live lease fills in. Returns "" when no managed record ties
// the address to a device.
func (s *Server) macAtIP(ctx context.Context, ip string) string {
	if s.kea == nil {
		return ""
	}
	leases, err := s.kea.GetLeases(ctx, 1000)
	if err != nil {
		return ""
	}
	for _, l := range activeLeases(leases) {
		if l.IPAddress == ip {
			if mac := liveMAC(l.HWAddress); mac != "" {
				return mac
			}
		}
	}
	return ""
}
