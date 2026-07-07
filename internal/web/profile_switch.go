package web

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"ggo-kea-dhcp/internal/db"
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
	allTagged       bool   // every scope is tagged - reconnect IP is VLAN-only (interstitial warns)
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
	_, _ = io.WriteString(w, interstitialHTML(plan.gatewayIP, plan.allTagged))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go s.runRecoveredReconcile("finish-switch", func() { s.finishSwitch(plan, actor) })
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
	s.setFlash(w, r, "Deleted configuration "+name, "success")
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
	// Catch a bad topology (duplicate VLAN, overlapping CIDRs) that an import or
	// backup-restore could have written into this stored profile - kea -t won't.
	if err := validateScopeTopology(scopes); err != nil {
		return switchPlan{}, fmt.Errorf("Profile %q: %w", name, err)
	}

	// Render + validate + claim the guard + snapshot, guard held on success (shared
	// with beginApply). The uplink toggle comes from the box-level setting, not a form.
	boxUplink, _, _ := s.uplinkSettings()
	renderScopes, gatewayIP := buildRenderScopes(scopes, boxUplink)
	snapPath, err := s.prepareReconcile(renderScopes, "pre-switch")
	if err != nil {
		return switchPlan{}, err
	}

	plan := switchPlan{targetProfileID: targetID, profileName: name, snapPath: snapPath, gatewayIP: gatewayIP, allTagged: allScopesTagged(scopes)}
	_ = s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&plan.prevProfileID)

	tx, err := s.sqlite.Begin()
	if err != nil {
		s.endReconcile()
		return switchPlan{}, fmt.Errorf("Database error: %w", err)
	}
	// Every statement is load-bearing: a silently-failed active-flag toggle would
	// commit a tree with no (or two) active profiles. SQLite does not fail Commit for
	// a prior statement error, so each is checked and rolls the whole switch back.
	_, e1 := tx.Exec("UPDATE profiles SET active = 0")
	_, e2 := tx.Exec("UPDATE profiles SET active = 1 WHERE id = ?", targetID)
	_, e3 := tx.Exec(`
		INSERT INTO app_state (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		db.LifecycleStateKey, db.StateConfiguring)
	if err := errors.Join(e1, e2, e3); err != nil {
		_ = tx.Rollback()
		s.endReconcile()
		return switchPlan{}, fmt.Errorf("Failed to switch active profile: %w", err)
	}
	if err := tx.Commit(); err != nil {
		s.endReconcile()
		return switchPlan{}, fmt.Errorf("Failed to switch active profile: %w", err)
	}
	// Committed to the switch: tear down the old profile's monitors and DNS before
	// the CONFIGURING re-IP window (finishSwitch reconciles next). reconcileActive
	// restarts everything once the new interfaces are up.
	s.stopActiveMonitors()
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
		s.setActiveAudited("SWITCH_PROFILE", plan.profileName)
		_ = s.sqlite.LogAudit(actor, "SWITCH_PROFILE", plan.profileName, "", "", "SUCCESS")
		log.Printf("[Switch] Switched to profile %q; appliance is ACTIVE.", plan.profileName)
		s.publishDashboard()
		return
	} else {
		log.Printf("[Switch] Switch to %q failed, rolling back: %v", plan.profileName, err)
	}

	// Failure: revert the active flag, restore the snapshot, return to ACTIVE (a
	// switch originates from ACTIVE, unlike the setup apply), and reconcile back -
	// the failure tail shared with finishApply.
	s.rollbackFailed(rollbackSpec{
		tag:           "Switch",
		action:        "SWITCH_PROFILE",
		profileName:   plan.profileName,
		actor:         actor,
		revertState:   db.StateActive,
		prevProfileID: plan.prevProfileID,
		snapPath:      plan.snapPath,
		revertTables:  func() error { return s.revertActiveFlag(plan.prevProfileID) },
	})
}

// revertActiveFlag flips the active profile back to prevProfileID (or leaves no
// profile active when it is 0) after a failed switch, in one transaction.
// Deliberately all-or-nothing, which CHANGES the double-fault semantics: if the
// re-activation UPDATE fails, the whole revert rolls back and the FAILED target
// stays active=1, so the next boot retries the failed profile (and fails again,
// still serving the restored on-disk conf). The prior code committed the
// deactivation alone in that case, leaving NO active profile - which reads as an
// empty appliance and, with the zero-scopes rescue, demotes a serving box to
// onboarding. Retrying a known-bad profile is the safer double-fault.
func (s *Server) revertActiveFlag(prevProfileID int) error {
	rtx, err := s.sqlite.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = rtx.Rollback() }()
	_, e1 := rtx.Exec("UPDATE profiles SET active = 0")
	var e2 error
	if prevProfileID != 0 {
		_, e2 = rtx.Exec("UPDATE profiles SET active = 1 WHERE id = ?", prevProfileID)
	}
	if err := errors.Join(e1, e2); err != nil {
		return err
	}
	return rtx.Commit()
}
