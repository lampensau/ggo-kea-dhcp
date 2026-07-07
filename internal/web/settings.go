package web

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/web/views"
)

// globalDHCPOptions returns the site-wide DHCP option defaults (every scope inherits
// them unless it overrides per-scope). When the key is unset it migrates a previously
// chosen legacy uplink_dns resolver into the global DNS default - the bare 1.1.1.1
// default is NOT migrated, since a global default must be an explicit operator choice.
func (s *Server) globalDHCPOptions() GlobalDHCPOptions {
	var g GlobalDHCPOptions
	if v, _ := s.sqlite.GetState("global_dhcp_options"); v != "" {
		if err := json.Unmarshal([]byte(v), &g); err != nil {
			log.Printf("[settings] malformed global_dhcp_options - ignoring: %v", err)
			return GlobalDHCPOptions{}
		}
		return g
	}
	if v, _ := s.sqlite.GetState("uplink_dns"); v != "" && v != "disabled" {
		g.DNS = v
	}
	return g
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	g := s.globalDHCPOptions()
	gOpts := make([]views.ScopeOptionRow, 0, len(g.Options))
	for _, o := range g.Options {
		gOpts = append(gOpts, views.ScopeOptionRow{Name: o.Name, Data: o.Data})
	}
	ssid, pass := s.softAPSettings()

	// WiFi uplink is editable only in ACTIVE (before that wlan0 hosts the
	// onboarding SoftAP). The credentials are box-level (one wlan0); which scopes route
	// through it is the per-scope toggle on /pools.
	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	showUplink := state == db.StateActive
	upEnabled, upSSID, upPass := s.uplinkSettings()

	page := s.pageData(w, r, "Settings")
	s.renderTempl(w, r, views.Settings(views.SettingsView{
		Page:           page,
		OnboardingIP:   s.onboardingCIDR(),
		SoftAPSSID:     ssid,
		SoftAPPass:     pass,
		GlobalDNS:      g.DNS,
		GlobalOptions:  gOpts,
		ShowUplink:     showUplink,
		UplinkEnabled:  upEnabled,
		UplinkSSID:     upSSID,
		UplinkPassword: upPass,
		LeaseLifetime:  s.leaseLifetime(),
	}))
}

// settingsDeferredMsg tells the operator a save persisted but did NOT converge
// (the box is mid-apply in CONFIGURING, where no reconcile can run). There is no
// queue that re-applies the values, so the message asks for an explicit re-save
// rather than implying an automatic retry that never comes.
const settingsDeferredMsg = "Settings saved but NOT yet applied - another configuration change is in progress. Save again once it finishes to apply them."

// settingsBusyMsg tells the operator a save was refused outright because another
// configuration change holds the mutation guard. Nothing was persisted - saving
// mid-apply would let the apply's failure rollback silently clobber the values.
const settingsBusyMsg = "Settings NOT saved - another configuration change is in progress. Save again once it finishes."

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.handleError(w, r, "invalid form data", http.StatusBadRequest)
		return
	}

	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	oldCIDR := s.onboardingCIDR()

	// Validate every field FIRST, accumulating the app_state writes, so a later
	// validation failure can't leave earlier settings half-applied.
	updates := make(map[string]string)

	// --- Onboarding management IP/CIDR ---
	newCIDR := strings.TrimSpace(r.FormValue("onboarding_ip"))
	if newCIDR != "" {
		ip, _, err := net.ParseCIDR(newCIDR)
		if err != nil || ip.To4() == nil {
			s.handleError(w, r, "Onboarding IP must be a valid IPv4 CIDR (e.g. 10.0.0.1/24)", http.StatusBadRequest)
			return
		}
		updates["onboarding_ip"] = newCIDR
	}

	// --- SoftAP ---
	softapSSID := strings.TrimSpace(r.FormValue("softap_ssid"))
	softapPass := r.FormValue("softap_pass")
	if msg := validateSoftAPSave(softapSSID, softapPass); msg != "" {
		s.handleError(w, r, msg, http.StatusBadRequest)
		return
	}
	if softapSSID != "" {
		updates["softap_ssid"] = softapSSID
	}
	updates["softap_pass"] = softapPass // empty clears it back to an open network

	// --- DHCP lease lifetime (seconds) --- a soft change: applied to the active profile
	// via a config-reload below (no re-IP). Validated to a sane range.
	leaseChanged := false
	if v := strings.TrimSpace(r.FormValue("lease_lifetime")); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil || secs < 30 || secs > 86400 {
			s.handleError(w, r, "Lease time must be a whole number of seconds between 30 and 86400", http.StatusBadRequest)
			return
		}
		if secs != s.leaseLifetime() {
			leaseChanged = true
		}
		updates["lease_lifetime"] = strconv.Itoa(secs)
	}

	// --- Global DHCP option defaults (DNS + extra options; every scope inherits
	// unless it overrides per-scope on /pools). Reuse the per-scope parser for the
	// shared DNS/option validation, ignoring its gateway/lease fields. A global option
	// change is a soft change applied on the next reconcile (config-reload, no re-IP).
	gsvc, gerr := parseScopeServices("", r.FormValue("global_dns"), "", "", r.Form["opt_name[]"], r.Form["opt_data[]"])
	if gerr != nil {
		s.handleError(w, r, gerr.Error(), http.StatusBadRequest)
		return
	}
	gJSON, _ := json.Marshal(GlobalDHCPOptions{DNS: gsvc.DNS, Options: gsvc.Options})
	globalOptsChanged := false
	if cur, _ := s.sqlite.GetState("global_dhcp_options"); cur != string(gJSON) {
		globalOptsChanged = true
	}
	updates["global_dhcp_options"] = string(gJSON)

	// --- WiFi uplink (ACTIVE only) --- box-level credentials for the one wlan0. WHICH
	// scopes route through it is the per-scope toggle on /pools. Validate now; persist
	// to app_state and let the soft reconcile below re-render Kea (gateway gating) and
	// (re)connect/tear down wlan0. Only acted on when it actually changed.
	upChanged := false
	var upTarget string
	if state == db.StateActive {
		cfg, uerr := parseUplinkForm(r)
		if uerr != nil {
			s.handleError(w, r, uerr.Error(), http.StatusBadRequest)
			return
		}
		curEn, curSSID, curPass := s.uplinkSettings()
		// When the uplink is off its SSID/pass fields are disabled and don't submit, so
		// keep the stored credentials (re-enabling restores them) instead of wiping them.
		ssid, pass := curSSID, curPass
		if cfg.Enabled {
			ssid, pass = cfg.SSID, cfg.Password
		}
		upChanged = cfg.Enabled != curEn || ssid != curSSID || pass != curPass
		for k, v := range uplinkState(cfg.Enabled, ssid, pass) {
			updates[k] = v
		}
		upTarget = cfg.SSID
		if !cfg.Enabled {
			upTarget = "disabled"
		}
	}

	// Claim the shared mutation guard BEFORE persisting anything the apply rollback
	// also owns: beginApply captures the uplink keys and finishApply's failure path
	// restores them, all under this guard - a save persisted mid-apply would be
	// silently clobbered by that restore. Refusing up front (values NOT saved, honest
	// deferred flash) closes the window; the pre-ACTIVE and soft-change branches
	// below need the guard for their reconcile anyway.
	needGuard := state == db.StateOnboarding || state == db.StateFactory ||
		(state == db.StateActive && (leaseChanged || globalOptsChanged || upChanged))
	if needGuard && !s.beginReconcile() {
		s.setFlash(w, r, settingsBusyMsg, "info")
		s.redirectHTMX(w, r, "/settings")
		return
	}

	// All validation passed - commit the settings atomically. (The admin-account
	// rename/password flow moved to the header account dialog, POST /account/save.)
	if err := s.sqlite.SetStates(updates); err != nil {
		if needGuard {
			s.endReconcile()
		}
		s.handleError(w, r, "Failed to save settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	actor := s.getActor(r)
	_ = s.sqlite.LogAudit(actor, "UPDATE_SETTINGS", "settings", "", "", "SUCCESS")
	if upChanged {
		_ = s.sqlite.LogAudit(actor, "UPDATE_UPLINK", upTarget, "", "", "SUCCESS")
	}

	// Live convergence is only safe pre-ACTIVE - never bounce links during a
	// live show. In ACTIVE the saved values take effect on the next apply/reset.
	if state == db.StateConfiguring {
		// An apply/switch is mid-flight (the route stays reachable in CONFIGURING).
		// The values are persisted but no reconcile can run now, and whether the
		// in-flight apply picks them up depends on where it happened to be - so
		// give the same honest deferred message the guard-busy paths use instead
		// of a success flash that implies the change is live.
		msg := settingsDeferredMsg
		// A form rendered while still ACTIVE carries the uplink section (its
		// hidden uplink_form marker survives even a disable, which submits no
		// other uplink fields), but the uplink block above runs only in ACTIVE -
		// a submit landing after the flip drops the section entirely. Warn only
		// when the submitted intent actually differs from what is stored, so a
		// lease-time-only save is not blamed for uplink changes it never made.
		if r.Form.Has("uplink_form") {
			if cfg, uerr := parseUplinkForm(r); uerr == nil {
				curEn, curSSID, curPass := s.uplinkSettings()
				changed := cfg.Enabled != curEn ||
					(cfg.Enabled && (cfg.SSID != curSSID || cfg.Password != curPass))
				if changed {
					msg += " WiFi uplink changes were NOT saved - reopen Settings once the change finishes."
				}
			}
		}
		s.setFlash(w, r, msg, "info")
		s.redirectHTMX(w, r, "/settings")
		return
	}
	if state == db.StateOnboarding || state == db.StateFactory {
		ipChanged := newCIDR != "" && newCIDR != oldCIDR
		delay := time.Duration(0)
		if ipChanged {
			delay = 1 * time.Second // let the interstitial reach the client first
		}
		// The guard was claimed before the persist above (needGuard covers this state).
		s.scheduleReconcileHeld("settings", delay, ModeConverge, 0)
		// If the management IP changed, the current connection is about to drop -
		// hand the operator the reconnect interstitial pointed at the new IP.
		if ipChanged {
			s.respondInterstitial(w, ipOnly(newCIDR))
			return
		}
	} else if state == db.StateActive && (leaseChanged || globalOptsChanged || upChanged) {
		// A lease-time, global-DHCP-options, or WiFi-uplink change in ACTIVE is a soft
		// change: a ModeConverge reconcile re-renders Kea (lease/options/gateway gating)
		// and (re)connects or tears down wlan0 + NAT. No re-IP and no interface bounce,
		// so this is safe mid-show (unlike a CIDR/uplink change) - no interstitial. The
		// guard was claimed before the persist above (needGuard covers this state).
		s.scheduleReconcileHeld("settings-soft", 0, ModeConverge, 0)
	}

	s.setFlash(w, r, "Settings saved.", "success")
	s.redirectHTMX(w, r, "/settings")
}

// activeProfileUplink returns the active profile's id and its uplink config. The
// uplink is conceptually one per box; it is persisted on every scope row, so we
// return the first enabled scope's uplink (else the first scope's). ok is false
// when there is no active profile or it has no scopes.
func (s *Server) activeProfileUplink() (profileID int, cfg UplinkConfig, ok bool) {
	if err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID); err != nil {
		return 0, UplinkConfig{}, false
	}
	scopes, err := s.loadScopeConfigs(profileID)
	if err != nil || len(scopes) == 0 {
		return profileID, UplinkConfig{}, false
	}
	for _, sc := range scopes {
		if sc.Uplink.Enabled {
			return profileID, sc.Uplink, true
		}
	}
	return profileID, scopes[0].Uplink, true
}
