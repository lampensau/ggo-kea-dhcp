package web

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// switchPlan carries state from the synchronous beginSwitch to the asynchronous
// finishSwitch, mirroring applyPlan but for activating an already-saved profile.
type switchPlan struct {
	targetProfileID int
	prevProfileID   int
	profileName     string
	snapPath        string
	gatewayIP       string // the address the operator's browser reconnects to
}

// listProfiles returns every saved profile (active first, then newest) with its
// scope count, for the dashboard's profile switcher. Errors yield no profiles
// rather than failing the page.
func (s *Server) listProfiles() []views.ProfileOption {
	// Exclude rollback stashes (persistProfile renames a replaced same-named
	// profile aside as "<name>.stash-<id>"): they are transient and must never
	// appear as an activatable/deletable entry in the switcher.
	rows, err := s.sqlite.Query(`
		SELECT p.id, p.name, p.active, COUNT(sc.id)
		FROM profiles p
		LEFT JOIN scopes sc ON sc.profile_id = p.id
		WHERE p.name NOT GLOB '*.stash-[0-9]*'
		GROUP BY p.id, p.name, p.active
		ORDER BY p.active DESC, p.id DESC`)
	if err != nil {
		log.Printf("[Profiles] list: %v", err)
		return nil
	}
	defer rows.Close()

	var out []views.ProfileOption
	for rows.Next() {
		var o views.ProfileOption
		var active int
		if err := rows.Scan(&o.ID, &o.Name, &active, &o.ScopeCount); err != nil {
			continue
		}
		o.Active = active == 1
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[Profiles] list iteration: %v", err)
	}
	return out
}

// handleProfileActivate switches the appliance to another saved profile. Like the
// setup apply it re-IPs the box, so it flushes the reconnect interstitial between
// a synchronous validate/persist (beginSwitch) and an async reconcile
// (finishSwitch), while the old IP still works.
func (s *Server) handleProfileActivate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.handleError(w, r, "invalid form data", http.StatusBadRequest)
		return
	}
	targetID, _ := strconv.Atoi(r.FormValue("profile_id"))
	if targetID <= 0 {
		s.handleError(w, r, "invalid profile", http.StatusBadRequest)
		return
	}

	plan, err := s.beginSwitch(targetID)
	if err != nil {
		s.handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	actor := s.getActor(r)

	// Flush the interstitial NOW, while the old IP still answers - the imminent
	// re-IP will drop this very connection.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, interstitialHTML(plan.gatewayIP))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go s.finishSwitch(plan, actor)
}

// handleProfileDelete removes a saved (non-active) profile. The active profile is
// never deletable. A native POST that redirects back to the dashboard with the
// list refreshed (no re-IP, so no interstitial).
func (s *Server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.handleError(w, r, "invalid form data", http.StatusBadRequest)
		return
	}
	id, _ := strconv.Atoi(r.FormValue("profile_id"))
	if id <= 0 {
		s.handleError(w, r, "invalid profile", http.StatusBadRequest)
		return
	}

	var active int
	var name string
	if err := s.sqlite.QueryRow("SELECT active, name FROM profiles WHERE id = ?", id).Scan(&active, &name); err != nil {
		s.handleError(w, r, "profile not found", http.StatusNotFound)
		return
	}
	if active == 1 {
		s.handleError(w, r, "Cannot delete the active configuration.", http.StatusBadRequest)
		return
	}
	// active = 0 in the WHERE clause is belt-and-braces against a race.
	if _, err := s.sqlite.Exec("DELETE FROM profiles WHERE id = ? AND active = 0", id); err != nil {
		s.handleError(w, r, "Failed to delete profile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "DELETE_PROFILE", name, "", "", "SUCCESS")
	s.setFlash(w, "Deleted configuration "+name, "success")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// beginSwitch validates the target profile's config, snapshots the current one,
// flips the active flag, and enters CONFIGURING - all before the interstitial is
// flushed (so a crash mid-switch is recovered on boot, and the interstitial's
// /dashboard probe isn't bounced). It leaves the box untouched on any error.
func (s *Server) beginSwitch(targetID int) (switchPlan, error) {
	var name string
	var active int
	if err := s.sqlite.QueryRow("SELECT name, active FROM profiles WHERE id = ?", targetID).Scan(&name, &active); err != nil {
		return switchPlan{}, fmt.Errorf("Profile not found.")
	}
	if active == 1 {
		return switchPlan{}, fmt.Errorf("That profile is already active.")
	}
	scopes, err := s.loadScopeConfigs(targetID)
	if err != nil || len(scopes) == 0 {
		return switchPlan{}, fmt.Errorf("Profile %q has no scopes to apply.", name)
	}

	// Render + validate the candidate before anything irreversible.
	boxUplink, _, _ := s.uplinkSettings()
	renderScopes, gatewayIP := buildRenderScopes(scopes, boxUplink)
	host, user, dbpass, dbname := config.ParseMariaDSN(s.cfg.MariaDBDSN)
	g := s.globalDHCPOptions()
	configStr, _, err := kea.RenderProfile(kea.ProfileRenderInput{
		Scopes:        renderScopes,
		MariaDBHost:   host,
		MariaDBUser:   user,
		MariaDBPass:   dbpass,
		MariaDBName:   dbname,
		KeaSecretPath: s.cfg.KeaSecretPath,
		GlobalDNS:     g.DNS,
		GlobalOptions: g.keaOptions(),
		// Validate on "*": the target profile's VLAN interfaces aren't created until the
		// reconcile below, so a per-interface kea -t here would fail "interface doesn't
		// exist". writeAndReloadKea re-validates the real config once they're up.
		IfaceWildcard: true,
	})
	if err != nil {
		return switchPlan{}, fmt.Errorf("Failed to generate configuration for %q: %w", name, err)
	}
	if err := kea.TestConfig(configStr); err != nil {
		return switchPlan{}, fmt.Errorf("Configuration for %q failed validation: %w", name, err)
	}

	// Claim the shared mutation guard BEFORE writing any persistent artifact, so a
	// guard-loser can't orphan a snapshot file + config_snapshots row (beginApply also
	// claims first). snapshotKeaConf then runs under the guard, never racing an
	// in-flight apply that is mid-writing the conf.
	if !s.beginReconcile() {
		return switchPlan{}, fmt.Errorf("A profile apply is already in progress.")
	}

	snapPath, err := s.snapshotKeaConf("pre-switch")
	if err != nil {
		s.endReconcile()
		return switchPlan{}, fmt.Errorf("Failed to snapshot current configuration: %w", err)
	}

	plan := switchPlan{targetProfileID: targetID, profileName: name, snapPath: snapPath, gatewayIP: gatewayIP}
	_ = s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&plan.prevProfileID)

	tx, err := s.sqlite.Begin()
	if err != nil {
		s.endReconcile()
		return switchPlan{}, fmt.Errorf("Database error: %w", err)
	}
	_, _ = tx.Exec("UPDATE profiles SET active = 0")
	_, _ = tx.Exec("UPDATE profiles SET active = 1 WHERE id = ?", targetID)
	_, _ = tx.Exec(`
		INSERT INTO app_state (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		db.LifecycleStateKey, db.StateConfiguring)
	if err := tx.Commit(); err != nil {
		s.endReconcile()
		return switchPlan{}, fmt.Errorf("Failed to switch active profile: %w", err)
	}
	// Committed to the switch: tear down the old profile's monitors before the
	// CONFIGURING re-IP window (finishSwitch reconciles next). reconcileActive
	// restarts them once the new interfaces are up.
	if s.netmon != nil {
		s.netmon.Stop()
	}
	if s.arp != nil {
		s.arp.Stop()
	}
	if s.ggoscan != nil {
		s.ggoscan.Stop()
	}
	return plan, nil
}

// finishSwitch reconciles runtime state to the now-active profile and, on success,
// returns to ACTIVE. On failure it reverts the active flag to the previous profile,
// restores the snapshot, reconciles back, and stays ACTIVE (a switch originates
// from ACTIVE, unlike the setup apply which reverts to ONBOARDING). It always
// clears the apply guard.
func (s *Server) finishSwitch(plan switchPlan, actor string) {
	defer s.endReconcile()
	time.Sleep(1 * time.Second) // let the flushed interstitial bytes drain to the client

	if err := s.ReconcileApplianceState(ModeApply, plan.targetProfileID); err == nil {
		if e := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); e != nil {
			log.Printf("[Switch] failed to persist ACTIVE state: %v", e)
		}
		_ = s.sqlite.LogAudit(actor, "SWITCH_PROFILE", plan.profileName, "", "", "SUCCESS")
		log.Printf("[Switch] Switched to profile %q; appliance is ACTIVE.", plan.profileName)
		s.publishDashboard()
		return
	} else {
		log.Printf("[Switch] Switch to %q failed, rolling back: %v", plan.profileName, err)
	}

	// Failure: revert the active flag to the previous profile. Best-effort, but log
	// a failed revert - a silent failure can leave the box with no active profile.
	if rtx, e := s.sqlite.Begin(); e != nil {
		log.Printf("[Switch] rollback: begin tx: %v", e)
	} else {
		_, e1 := rtx.Exec("UPDATE profiles SET active = 0")
		var e2 error
		if plan.prevProfileID != 0 {
			_, e2 = rtx.Exec("UPDATE profiles SET active = 1 WHERE id = ?", plan.prevProfileID)
		}
		if err := errors.Join(e1, e2, rtx.Commit()); err != nil {
			log.Printf("[Switch] rollback: revert active profile: %v", err)
		}
	}

	// Restore the snapshot conf and reload Kea.
	if plan.snapPath != "" {
		if data, e := os.ReadFile(plan.snapPath); e == nil {
			live := filepath.Join(s.cfg.KeaConfDir, "kea-dhcp4.conf")
			if e := os.WriteFile(live, data, 0660); e != nil {
				log.Printf("[Switch] rollback: restore snapshot conf: %v", e)
			} else if e := s.kea.ReloadConfig(); e != nil {
				log.Printf("[Switch] rollback: Kea reload after restore: %v", e)
			}
		}
	}

	// Restore ACTIVE before reconciling so the reconcile dispatches straight to
	// reconcileActive (a switch originates from ACTIVE, not CONFIGURING/ONBOARDING).
	if e := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); e != nil {
		log.Printf("[Switch] failed to restore ACTIVE state: %v", e)
	}
	// ModeApply (not Converge) so the full NM teardown removes any connection the
	// failed forward switch created for a scope the previous profile lacks - else a
	// stale interface lingers, addressing diverging from the served subnets.
	if e := s.ReconcileApplianceState(ModeApply, plan.prevProfileID); e != nil {
		log.Printf("[Switch] Rollback reconcile reported: %v", e)
	}
	_ = s.sqlite.LogAudit(actor, "SWITCH_PROFILE", plan.profileName, "", "", "FAILED")
}
