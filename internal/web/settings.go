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

	s.renderTempl(w, r, views.Settings(views.SettingsView{
		Page:           s.pageData(w, r, "Settings"),
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
		Username:       s.getActor(r),
	}))
}

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
	if ssid := strings.TrimSpace(r.FormValue("softap_ssid")); ssid != "" {
		updates["softap_ssid"] = ssid
	}
	softapPass := r.FormValue("softap_pass")
	if softapPass != "" && len(softapPass) < 8 {
		s.handleError(w, r, "SoftAP password must be at least 8 characters (WPA2), or empty for an open network", http.StatusBadRequest)
		return
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
	gsvc, gerr := parseScopeServices("", r.FormValue("global_dns"), "", r.Form["opt_name[]"], r.Form["opt_data[]"])
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
		en := "0"
		ssid, pass := curSSID, curPass
		if cfg.Enabled {
			en = "1"
			ssid, pass = cfg.SSID, cfg.Password
		}
		upChanged = cfg.Enabled != curEn || ssid != curSSID || pass != curPass
		updates["uplink_enabled"] = en
		updates["uplink_ssid"] = ssid
		updates["uplink_pass"] = pass
		upTarget = cfg.SSID
		if !cfg.Enabled {
			upTarget = "disabled"
		}
	}

	// --- Admin account (optional username rename + password change) --- validate now,
	// apply after the state writes succeed. Either change is "sensitive" and requires
	// the current password; the username keys the session, so a rename also rewrites
	// the live session rows.
	actor := s.getActor(r)
	newUsername := strings.TrimSpace(r.FormValue("username"))
	usernameChanged := newUsername != "" && newUsername != actor
	if usernameChanged {
		if len(newUsername) < 3 || len(newUsername) > 32 || strings.ContainsAny(newUsername, " \t") {
			s.handleError(w, r, "Username must be 3-32 characters with no spaces", http.StatusBadRequest)
			return
		}
		var n int
		if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", newUsername).Scan(&n); err != nil {
			s.handleError(w, r, "Database error checking username", http.StatusInternalServerError)
			return
		} else if n > 0 {
			s.handleError(w, r, "That username is already taken", http.StatusBadRequest)
			return
		}
	}

	newPass := r.FormValue("new_password")
	var newPassHash string
	if newPass != "" {
		if newPass != r.FormValue("confirm_password") {
			s.handleError(w, r, "New passwords do not match", http.StatusBadRequest)
			return
		}
		if len(newPass) < 12 {
			s.handleError(w, r, "New password must be at least 12 characters long", http.StatusBadRequest)
			return
		}
		hashed, err := hashPassword(newPass)
		if err != nil {
			s.handleError(w, r, "internal server error", http.StatusInternalServerError)
			return
		}
		newPassHash = hashed
	}

	// Any sensitive account change (rename or new password) requires the current
	// password, verified once against the still-current username.
	if usernameChanged || newPassHash != "" {
		var stored string
		if err := s.sqlite.QueryRow("SELECT password_hash FROM users WHERE username = ?", actor).Scan(&stored); err != nil {
			s.handleError(w, r, "Could not load current credentials", http.StatusInternalServerError)
			return
		}
		if !verifyPassword(stored, r.FormValue("current_password")) {
			s.handleError(w, r, "Current password is incorrect", http.StatusBadRequest)
			return
		}
	}

	// All validation passed - commit the settings atomically.
	if err := s.sqlite.SetStates(updates); err != nil {
		s.handleError(w, r, "Failed to save settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Password first (keyed on the current username), then the rename, so the rename's
	// session/users rewrite doesn't strand the password update.
	if newPassHash != "" {
		if _, err := s.sqlite.Exec("UPDATE users SET password_hash = ? WHERE username = ?", newPassHash, actor); err != nil {
			s.handleError(w, r, "Failed to update password", http.StatusInternalServerError)
			return
		}
		// A password change logs out every OTHER session (a forgotten browser or a
		// suspected-compromise device), keeping only the current one. Keyed on the
		// still-current username, before any rename below.
		if c, err := r.Cookie(sessionCookieName); err == nil {
			_, _ = s.sqlite.Exec("DELETE FROM sessions WHERE username = ? AND session_id != ?", actor, c.Value)
		}
		_ = s.sqlite.LogAudit(actor, "CHANGE_PASSWORD", actor, "", "", "SUCCESS")
	}
	if usernameChanged {
		if _, err := s.sqlite.Exec("UPDATE users SET username = ? WHERE username = ?", newUsername, actor); err != nil {
			s.handleError(w, r, "Failed to rename administrator: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Keep every live session for this admin valid (the session cookie maps to a
		// sessions row keyed by username), so the rename doesn't log the operator out.
		if _, err := s.sqlite.Exec("UPDATE sessions SET username = ? WHERE username = ?", newUsername, actor); err != nil {
			log.Printf("[settings] renamed user but failed to update sessions: %v", err)
		}
		_ = s.sqlite.LogAudit(newUsername, "CHANGE_USERNAME", actor+" -> "+newUsername, "", "", "SUCCESS")
		actor = newUsername
	}

	_ = s.sqlite.LogAudit(actor, "UPDATE_SETTINGS", "settings", "", "", "SUCCESS")
	if upChanged {
		_ = s.sqlite.LogAudit(actor, "UPDATE_UPLINK", upTarget, "", "", "SUCCESS")
	}

	// Live convergence is only safe pre-ACTIVE - never bounce links during a
	// live show. In ACTIVE the saved values take effect on the next apply/reset.
	if state == db.StateOnboarding || state == db.StateFactory {
		ipChanged := newCIDR != "" && newCIDR != oldCIDR
		delay := time.Duration(0)
		if ipChanged {
			delay = 1 * time.Second // let the interstitial reach the client first
		}
		// Serialize against an in-flight apply/switch: refuse to bounce links under
		// another reconcile. The values are persisted, but there is no queue that
		// re-applies them when the guard frees - so tell the operator the change is NOT
		// yet live and to save again once the in-flight change completes (rather than
		// implying an automatic retry that never comes).
		if !s.beginReconcile() {
			s.setFlash(w, "Settings saved but NOT yet applied - another configuration change is in progress. Save again once it finishes to apply them.", "info")
			s.redirectHTMX(w, r, "/settings")
			return
		}
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
		// so this is safe mid-show
		// (unlike a CIDR/uplink change) - no interstitial.
		if s.beginReconcile() {
			s.scheduleReconcileHeld("settings-soft", 0, ModeConverge, 0)
		} else {
			log.Printf("[settings] soft reconcile deferred - a configuration change is in progress")
		}
	}

	s.setFlash(w, "Settings saved.", "success")
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
