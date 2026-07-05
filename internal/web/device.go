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
// Trust boundary: the posted IP and MAC are client state and are never trusted for the
// Green-GO identity decision. The handler re-derives, from the IP alone, the device that
// actually holds the address right now - the MAC on its live Kea lease (or, once released,
// the MAC answering ARP at the IP), which must be a known Green-GO client. The posted MAC
// is then a freshness gate: it must equal that live MAC. This closes the re-issue window
// where the pool hands the just-released address to a different device between the offer
// and the confirm - the live MAC no longer matches, so the reboot is refused, not aimed at
// the wrong host. Any mismatch or unbacked IP is refused with 403 and audited.
func (s *Server) handleDeviceReboot(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	back := formReturn(r, "/dashboard")
	ip := strings.TrimSpace(r.FormValue("ip"))
	postedMAC := normalizeMAC(strings.TrimSpace(r.FormValue("mac")))

	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		s.handleError(w, r, "Enter a valid device address to reboot.", http.StatusBadRequest)
		return
	}

	name, liveMAC, ok := s.rebootEligible(r.Context(), ip)
	if !ok {
		// Not a reachable Green-GO client we manage: refuse and record the attempt.
		_ = s.sqlite.LogAudit(s.getActor(r), "DEVICE_REBOOT", ip, "", "not a reachable Green-GO device", "WARNING")
		s.handleError(w, r, ip+" is not a reachable Green-GO device, so there is nothing to reboot.", http.StatusForbidden)
		return
	}
	// Freshness gate: the device the operator was offered must still be the one at the
	// address. A blank or mismatched posted MAC means the address moved (or the request
	// was forged), so refuse rather than reboot whoever holds the IP now.
	if postedMAC == "" || postedMAC != liveMAC {
		_ = s.sqlite.LogAudit(s.getActor(r), "DEVICE_REBOOT", ip, postedMAC, "device at address changed since the offer ("+liveMAC+" now holds it)", "WARNING")
		s.handleError(w, r, "The device at "+ip+" changed since this was offered, so the reboot was not sent.", http.StatusForbidden)
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

// rebootEligible re-derives, server-side, the Green-GO client that currently holds ip,
// returning its display name and normalized live MAC when so. Eligibility is anchored to
// the address's live occupant, not the scan inventory's (up-to-15-min-stale) IP mapping:
// the MAC comes from the current Kea lease at ip, or - covering the just-released case
// where the lease is gone but the device is still physically there - from an ARP probe of
// the address. That MAC must belong to a known Green-GO device, and the address must be
// answering ARP right now. Never consults the posted form. The returned MAC is the
// freshness anchor the handler matches the posted MAC against.
func (s *Server) rebootEligible(ctx context.Context, ip string) (name, liveMAC string, ok bool) {
	reachable, available := s.presenceByIP()
	if !available || !reachable[ip] {
		return "", "", false // can't confirm the device is online - don't reboot into the void
	}
	mac := s.macAtIP(ctx, ip)
	if mac == "" && s.arp != nil {
		// Lease already gone (a release): the device is still on the wire, so ARP tells
		// us who actually answers at the address now.
		if m, alive := s.arp.ProbeHost(ip); alive {
			mac = m
		}
	}
	if mac == "" {
		return "", "", false // nothing ties the address to a device
	}
	dev, ok := s.ggoDeviceByMAC(mac)
	if !ok {
		return "", "", false // the address's live occupant is not a known Green-GO client
	}
	return rebootDeviceName(dev), normalizeMAC(mac), true
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
