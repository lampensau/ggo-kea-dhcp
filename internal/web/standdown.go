package web

import (
	"context"
	"fmt"
	"ggo-kea-dhcp/internal/appliance"
	"log"
	"net/http"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/netmon"
	"ggo-kea-dhcp/internal/web/views"
)

// rogueSighting is one foreign DHCP server the passive monitor currently sees.
// Count is how many foreign servers that interface's detector saw; the snapshot
// only exposes the first server's IP/MAC, so Count lets the banner report the honest
// total even when several answer on one interface.
type rogueSighting struct {
	Server string
	MAC    string
	Iface  string
	Count  int
	// Sustained is true once the detector has seen this interface's rogue across a
	// sustained run rather than a single (forgeable) frame. The loud stand-down banner
	// escalates only on a sustained sighting; the quieter Network Health row does not
	// wait. See netmon rogueSustainedAfter.
	Sustained bool
}

// activeRogues returns the foreign DHCP servers the monitor currently reports at
// error severity, across every served interface. Empty when netmon is absent
// (dev sandbox) or nothing rogue is visible.
func (s *Server) activeRogues() []rogueSighting {
	if s.mon.Netmon == nil {
		return nil
	}
	var out []rogueSighting
	for _, snap := range s.mon.Netmon.SnapshotAll() {
		for _, d := range snap.Detectors {
			if d.Kind == "rogue_dhcp" && d.Severity == netmon.SevError {
				count := 1
				if c, err := strconv.Atoi(d.Fields["count"]); err == nil && c > count {
					count = c
				}
				out = append(out, rogueSighting{
					Server:    d.Fields["server"],
					MAC:       d.Fields["mac"],
					Iface:     snap.Iface,
					Count:     count,
					Sustained: d.Fields["sustained"] == "1",
				})
			}
		}
	}
	return out
}

// totalRogues sums the foreign servers across every interface's sighting. Count is
// the per-interface tally (>=1); a zero Count (an unset/legacy sighting) counts as one
// so the total never drops below the number of sightings.
func totalRogues(rogues []rogueSighting) int {
	n := 0
	for _, r := range rogues {
		if r.Count < 1 {
			n++
			continue
		}
		n += r.Count
	}
	return n
}

// rogueAlertRows builds the loud #backend-alert rows for the rogue-server / stand-down
// state. While stood down it shows the operator-controlled hold state with a Resume
// control (persisting regardless of whether the rogue is still visible); otherwise it
// promotes a live rogue detection into an error row with a Stand Down control. Empty
// when neither applies, so a healthy box shows nothing here.
func (s *Server) rogueAlertRows() []views.AlertRow {
	return buildRogueRows(s.dhcpStoodDown(), s.activeRogues(), leaseExpiryPhrase(s.leaseLifetime()))
}

// buildRogueRows is the pure banner-row logic (split out so it is testable without a
// live monitor): the stood-down state wins over a live detection, since the operator's
// hold persists until they resume regardless of whether the rogue is still visible.
// leaseHint is the human lease-lifetime phrase (e.g. "about 30 minutes") threaded into
// the operator copy so the confirm dialog + stood-down banner can state honestly when
// devices lose their addresses.
//
// The loud row escalates only on a SUSTAINED rogue (anyRogueSustained): a single spoofed
// OFFER is a trivially LAN-forgeable outage lever, so a transient sighting stays in the
// quieter Network Health row and does not raise the one-click stand-down control here.
func buildRogueRows(stoodDown bool, rogues []rogueSighting, leaseHint string) []views.AlertRow {
	if stoodDown {
		return []views.AlertRow{{
			Severity:  "warn",
			Title:     "DHCP stood down by operator",
			Detail:    standDownBannerDetail(leaseHint),
			Action:    "resume",
			LeaseHint: leaseHint,
		}}
	}
	if !anyRogueSustained(rogues) {
		return nil
	}
	return []views.AlertRow{{
		Severity:  "err",
		Title:     rogueAlertTitle(rogues),
		Detail:    rogueAlertDetail(rogues),
		Action:    "standdown",
		LeaseHint: leaseHint,
	}}
}

// anyRogueSustained reports whether any sighting is a sustained rogue (see
// rogueSighting.Sustained) - the gate that keeps a one-shot forged OFFER from raising the
// loud stand-down banner.
func anyRogueSustained(rogues []rogueSighting) bool {
	for _, r := range rogues {
		if r.Sustained {
			return true
		}
	}
	return false
}

// standDownBannerDetail is the stood-down banner copy: honest that standing down only
// pauses OUR serving - the rogue is not stopped and devices lose their address as their
// current lease expires.
func standDownBannerDetail(leaseHint string) string {
	d := "This appliance is not handing out or renewing DHCP leases. The rogue server is not stopped, and devices will lose their address as each current lease expires"
	if leaseHint != "" {
		d += " (" + leaseHint + ")"
	}
	return d + ". Resume once the rogue server is disconnected."
}

// leaseExpiryPhrase renders a DHCP lease lifetime (seconds) as an approximate human
// phrase ("about 30 minutes") for the stand-down copy, or "" when it is unknown/invalid
// so callers can omit the parenthetical rather than print a bare number.
func leaseExpiryPhrase(secs int) string {
	if secs <= 0 {
		return ""
	}
	switch {
	case secs < 60:
		return "about " + plural(secs, "second")
	case secs < 3600:
		return "about " + plural(secs/60, "minute")
	default:
		return "about " + plural(secs/3600, "hour")
	}
}

// plural formats n with unit, appending "s" for anything but 1 (e.g. "1 hour",
// "30 minutes").
func plural(n int, unit string) string {
	s := strconv.Itoa(n) + " " + unit
	if n != 1 {
		s += "s"
	}
	return s
}

// rogueAlertTitle names the count of foreign servers in the banner headline, counting
// every server (not just one per interface) so several answering on one interface are
// reported honestly.
func rogueAlertTitle(rogues []rogueSighting) string {
	if total := totalRogues(rogues); total > 1 {
		return strconv.Itoa(total) + " rogue DHCP servers detected"
	}
	return "Rogue DHCP server detected"
}

// rogueAlertDetail spells out the offending server (first one named, with a count of
// any others) and why it matters. The "and N more" count spans every interface, so a
// second server on the same interface as the first is still counted even though the
// snapshot only exposes the first server's IP/MAC. templ auto-escapes them in the row.
func rogueAlertDetail(rogues []rogueSighting) string {
	if len(rogues) == 0 {
		return ""
	}
	first := rogues[0]
	who := first.Server
	if first.MAC != "" {
		who += " (" + first.MAC + ")"
	}
	if first.Iface != "" {
		who += " on " + first.Iface
	}
	if more := totalRogues(rogues) - 1; more > 0 {
		who += " and " + strconv.Itoa(more) + " more"
	}
	return who + " is answering DHCP - devices may lease from the wrong server. Standing our DHCP down pauses this appliance's serving; it does not remove the rogue."
}

// rogueAuditDetail is the audit-log detail: the server(s) that prompted the action,
// or a note that none is currently visible (an operator may stand down pre-emptively).
// Only the first server per interface is named (the snapshot exposes no more); when the
// true total exceeds the named servers, the tally is appended so the log isn't misleading.
func rogueAuditDetail(rogues []rogueSighting) string {
	if len(rogues) == 0 {
		return "no rogue server currently visible"
	}
	parts := make([]string, 0, len(rogues))
	for _, r := range rogues {
		who := r.Server
		if r.MAC != "" {
			who += " (" + r.MAC + ")"
		}
		parts = append(parts, who)
	}
	detail := strings.Join(parts, ", ")
	if total := totalRogues(rogues); total > len(parts) {
		detail += " (" + strconv.Itoa(total) + " servers total)"
	}
	return detail
}

// setStandDown persists the stand-down flag and audits the transition. Split from
// the handlers so the DB effects (flag + audit) are unit-testable without the async
// Kea reload, mirroring routineResetDB. rogueDetail names the server(s) that prompted
// a stand-down (ignored on resume).
func (s *Server) setStandDown(actor string, down bool, rogueDetail string) error {
	v := "0"
	if down {
		v = "1"
	}
	if err := s.sqlite.SetState(appliance.DHCPStandDownKey, v); err != nil {
		return err
	}
	if down {
		_ = s.sqlite.LogAudit(actor, "ROGUE_STANDDOWN", rogueDetail, "serving", "stood down", "WARNING")
	} else {
		_ = s.sqlite.LogAudit(actor, "ROGUE_RESUME", "", "stood down", "serving", "OK")
	}
	return nil
}

// applyDHCPServingState re-renders and reloads Kea to match the current stand-down
// flag, WITHOUT touching interfaces or NAT - so standing down / resuming is a fast
// Kea-only reload that never bounces the operator's link. The persisted flag is what
// makes a later full reconcile (reboot) honor the same state.
func (s *Server) applyDHCPServingState() error {
	scopes, err := s.loadScopeConfigs(0)
	if err != nil {
		return fmt.Errorf("load active scopes: %w", err)
	}
	if len(scopes) == 0 {
		return fmt.Errorf("no active profile scopes")
	}
	cfg, err := s.keaConfigForState(scopes)
	if err != nil {
		return err
	}
	// Same per-pass bound as the reconciler: writeAndReloadKea's dead-socket
	// fallback (service restart + reachability probe) can take well over opCtx.
	ctx, cancel := context.WithTimeout(context.Background(), appliance.ReconcilePassDeadline)
	defer cancel()
	return s.recon.WriteAndReloadKea(ctx, cfg)
}

// scheduleServingReloadHeld applies the current serving state (holdoff or profile) to
// Kea in the background, then releases the mutation guard the caller MUST already hold
// (via beginReconcile). Kea-only, so it never bounces the operator's link; the
// persisted flag is authoritative, so a reload failure only logs/audits - the next
// reconcile (or reboot) re-applies it.
//
// A failed background reload is dangerous in BOTH directions, because the persisted flag
// is flipped optimistically before the reload confirms - so on failure the flag asserts a
// state Kea is not actually in. Both branches correct the flag back to the truth so the
// operator is never shown a state that contradicts what Kea is serving:
//
//   - resuming: Kea is still running the holdoff (serving nothing) but the flag was
//     cleared - re-arm it so the stood-down banner + Resume control return (a retry
//     surface); never a green UI over a dark box.
//   - standing down: Kea is still SERVING the profile but the flag was set - clear it
//     back so the banner reflects the live server (the rogue row + Stand Down retry
//     return) instead of asserting "stood down" over a running server, and nudge the
//     operator that the action failed. Never "stood down" over a serving box.
func (s *Server) scheduleServingReloadHeld(label string, resuming bool) {
	go func() {
		defer s.endReconcile()
		if err := s.applyDHCPServingState(); err != nil {
			log.Printf("[%s] applying DHCP serving state: %v", label, err)
			_ = s.sqlite.LogAudit("SYSTEM", "RECONCILE_FAILED", label, "", err.Error(), "WARNING")
			if resuming {
				_ = s.sqlite.SetState(appliance.DHCPStandDownKey, "1")
				s.publishBackendAlert()
			} else {
				_ = s.sqlite.SetState(appliance.DHCPStandDownKey, "0")
				s.publishBackendAlert()
				s.publishStandDownFailToast()
			}
		}
	}()
}

// publishStandDownFailToast pushes the one-shot "stand down failed - still serving" toast
// to every connected page after a stand-down background reload fails. Edge-driven only
// (never in the connect snapshot), mirroring the Kea down-edge toast; nil-safe so the DB
// unit tests (no live hub) exercise the flag-clear without a panic.
func (s *Server) publishStandDownFailToast() {
	if s.live == nil {
		return
	}
	s.live.publishIfChanged("standdown-toast", renderFragment(views.StandDownFailToast(true)))
}

// handleStandDown stops the appliance serving DHCP on every scope in response to a
// detected rogue server. Explicit operator action only (never automatic): it persists
// the stand-down flag, audits the server(s) that prompted it, and reloads Kea with the
// holdoff config in the background. CSRF + auth are enforced by lifecycleMiddleware.
func (s *Server) handleStandDown(w http.ResponseWriter, r *http.Request) {
	// Record which foreign server(s) prompted this from the monitor, never from the
	// client (the value is attacker-influenced).
	detail := rogueAuditDetail(s.activeRogues())

	if !s.beginReconcile() {
		s.handleError(w, r, appliance.ReconcileBusyMsg, http.StatusConflict)
		return
	}
	if err := s.setStandDown(s.getActor(r), true, detail); err != nil {
		s.endReconcile()
		s.handleError(w, r, "Failed to persist the stand-down state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.scheduleServingReloadHeld("rogue-standdown", false) // background; releases the guard

	s.publishBackendAlert() // banner flips from the persisted flag, independent of the reload
	s.setFlash(w, r, "DHCP stood down - the appliance is no longer serving addresses. Resume once the rogue server is gone.", "success")
	s.redirectHTMX(w, r, backOrDashboard(r))
}

// handleResumeDHCP clears the stand-down flag and reloads Kea with the active profile
// config in the background, restoring normal serving on every scope. CSRF + auth
// enforced by lifecycleMiddleware.
func (s *Server) handleResumeDHCP(w http.ResponseWriter, r *http.Request) {
	if !s.beginReconcile() {
		s.handleError(w, r, appliance.ReconcileBusyMsg, http.StatusConflict)
		return
	}
	if err := s.setStandDown(s.getActor(r), false, ""); err != nil {
		s.endReconcile()
		s.handleError(w, r, "Failed to clear the stand-down state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.scheduleServingReloadHeld("rogue-resume", true) // background; releases the guard, re-arms on failure

	s.publishBackendAlert()
	s.setFlash(w, r, "DHCP resumed - the appliance is serving addresses again.", "success")
	s.redirectHTMX(w, r, backOrDashboard(r))
}

// backOrDashboard returns the same-site page the request came from, falling back to
// the dashboard - so a stand-down/resume from any page returns there.
func backOrDashboard(r *http.Request) string {
	back := refererPath(r)
	if !isValidRedirect(back) {
		return "/dashboard"
	}
	return back
}
