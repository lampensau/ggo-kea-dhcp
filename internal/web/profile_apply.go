package web

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

// applyPlan carries everything the asynchronous finishApply step needs, handed
// off from the synchronous beginApply step.
type applyPlan struct {
	newProfileID  int
	prevProfileID int
	// stashProfileID is a pre-existing same-named profile that persistProfile
	// renamed aside (instead of deleting) so a failed apply can restore it.
	// 0 when the applied name was new. Dropped by finishApply on success.
	stashProfileID int
	originState    string // lifecycle state the apply began in (revert target on failure)
	snapPath       string
	gatewayIP      string // the address the operator's browser reconnects to
}

// beginApply is the synchronous half of a profile apply: it renders + validates
// the candidate Kea config, snapshots the current one, persists the new
// profile/scopes, and transitions the appliance to the persisted CONFIGURING
// state - all BEFORE the caller flushes the reconnect interstitial. Entering
// CONFIGURING synchronously is what stops the interstitial's /dashboard probe
// from bouncing back to /setup (routing treats CONFIGURING like ACTIVE), and
// makes a crash before finishApply recoverable on boot. On any error it leaves
// the appliance untouched (state still ONBOARDING, apply guard cleared).
func (s *Server) beginApply(profileName string, scopes []ScopeConfig, uplink UplinkConfig) (applyPlan, error) {
	// Guard against concurrent applies first, so every irreversible side effect
	// below (monitor teardown, uplink + profile persistence, conf snapshot) is
	// serialized by one apply. A double-submit is rejected here before it can
	// clobber state. Cleared by finishApply's defer, or endReconcile on early error.
	if !s.beginReconcile() {
		return applyPlan{}, fmt.Errorf("A profile apply is already in progress.")
	}

	renderScopes, gatewayIP := buildRenderScopes(scopes, uplink.Enabled)

	host, user, dbpass, name := config.ParseMariaDSN(s.cfg.MariaDBDSN)
	g := s.globalDHCPOptions()
	configStr, _, err := kea.RenderProfile(kea.ProfileRenderInput{
		Scopes:        renderScopes,
		MariaDBHost:   host,
		MariaDBUser:   user,
		MariaDBPass:   dbpass,
		MariaDBName:   name,
		KeaSecretPath: s.cfg.KeaSecretPath,
		GlobalDNS:     g.DNS,
		GlobalOptions: g.keaOptions(),
		// Validate listening on "*": a VLAN scope's eth0.<vid> interface isn't created
		// until finishApply's reconcile, so a per-interface kea -t here would wrongly
		// fail "interface doesn't exist". The reconcile re-validates the real
		// per-interface config (writeAndReloadKea) once the interfaces are up.
		IfaceWildcard: true,
	})
	if err != nil {
		s.endReconcile()
		return applyPlan{}, fmt.Errorf("Failed to generate Kea configuration: %w", err)
	}

	// Validate the candidate before anything irreversible touches disk/Kea.
	if err := kea.TestConfig(configStr); err != nil {
		s.endReconcile()
		return applyPlan{}, fmt.Errorf("Generated configuration failed validation (kea-dhcp4 -t): %w", err)
	}

	// Persist the box-level WiFi uplink (one wlan0) only after the candidate
	// validates, so a render/validate failure can't leave wlan0's credentials
	// half-mutated. The reconcile reads these back to configure the uplink.
	en := "0"
	if uplink.Enabled {
		en = "1"
	}
	if err := s.sqlite.SetStates(map[string]string{"uplink_enabled": en, "uplink_ssid": uplink.SSID, "uplink_pass": uplink.Password}); err != nil {
		s.endReconcile()
		return applyPlan{}, fmt.Errorf("Failed to store WiFi uplink: %w", err)
	}

	// Snapshot the current live config so a failed apply can be rolled back.
	snapPath, err := s.snapshotKeaConf("pre-apply")
	if err != nil {
		s.endReconcile()
		return applyPlan{}, fmt.Errorf("Failed to snapshot current configuration: %w", err)
	}

	plan := applyPlan{snapPath: snapPath, gatewayIP: gatewayIP}
	plan.originState, _ = s.sqlite.GetState(db.LifecycleStateKey)
	_ = s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&plan.prevProfileID)

	// persistProfile writes the profile, its scopes, AND the CONFIGURING state in one
	// transaction (synchronously, before the interstitial is flushed - this is what
	// keeps the interstitial's /dashboard nav from bouncing back to /setup).
	if err := s.persistProfile(profileName, scopes, &plan); err != nil {
		s.endReconcile()
		return applyPlan{}, err
	}
	return plan, nil
}

// persistProfile writes the new (active) profile and its scopes in one
// transaction, setting plan.newProfileID. A pre-existing same-named profile is
// renamed aside and deactivated (not deleted), recorded in plan.stashProfileID,
// so a failed apply can restore the operator's prior config - re-applying the
// active profile's own name must not destroy it before the apply is known good.
// finishApply drops the stash on success; the failure path renames it back.
func (s *Server) persistProfile(profileName string, scopes []ScopeConfig, plan *applyPlan) error {
	tx, err := s.sqlite.Begin()
	if err != nil {
		return fmt.Errorf("Database error: %w", err)
	}
	var stashID int
	if e := tx.QueryRow("SELECT id FROM profiles WHERE name = ?", profileName).Scan(&stashID); e == nil {
		// Rename aside (name is UNIQUE) and deactivate. The stash name embeds the
		// id so it can't collide with another profile or a leftover stash.
		stashName := fmt.Sprintf("%s.stash-%d", profileName, stashID)
		if _, e := tx.Exec("UPDATE profiles SET name = ?, active = 0 WHERE id = ?", stashName, stashID); e != nil {
			_ = tx.Rollback()
			return fmt.Errorf("Failed to stash existing profile: %w", e)
		}
		plan.stashProfileID = stashID
	}
	_, _ = tx.Exec("UPDATE profiles SET active = 0")
	res, err := tx.Exec("INSERT INTO profiles (name, active) VALUES (?, 1)", profileName)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("Failed to store profile: %w", err)
	}
	id64, _ := res.LastInsertId()
	plan.newProfileID = int(id64)

	for _, sc := range scopes {
		ifaceMode := "physical"
		if sc.VlanID > 0 {
			ifaceMode = "trunk"
		}
		poolSpec, perr := sc.poolSpecJSON()
		uplinkSpec, uerr := sc.uplinkJSON()
		planJSON, plerr := sc.planJSON()
		servicesSpec, serr := sc.servicesJSON()
		if encErr := errors.Join(perr, uerr, plerr, serr); encErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("Failed to encode scope: %w", encErr)
		}
		if _, err := tx.Exec(`
			INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset, pool_spec, uplink_json, pool_plan, multicast_sniff, services_json, name)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			plan.newProfileID, ifaceMode, sc.VlanID, sc.CIDR, sc.Preset, poolSpec, uplinkSpec, planJSON, sc.MulticastSniff, servicesSpec, sc.Name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("Failed to store scope: %w", err)
		}
	}
	// Enter CONFIGURING in the SAME transaction as the profile/scope writes so the
	// state and the new active profile land atomically: a failure here can't leave a
	// committed-but-unreconciled profile with the box still in its prior state.
	if _, err := tx.Exec(`
		INSERT INTO app_state (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		db.LifecycleStateKey, db.StateConfiguring); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("Failed to enter CONFIGURING: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("Failed to commit profile: %w", err)
	}
	return nil
}

// finishApply is the asynchronous half: it reconciles runtime state to the new
// profile and, on success, transitions CONFIGURING → ACTIVE. On failure it
// reverts to ONBOARDING, restores the snapshot, drops the failed profile, and
// reconciles back. It always clears the in-process apply guard.
func (s *Server) finishApply(plan applyPlan, profileName, actor string) {
	defer s.endReconcile()

	// Tear down the prior profile's monitors before the imminent re-IP. Done here
	// (not in beginApply) so a beginApply that fails validation/snapshot leaves an
	// ACTIVE box's monitoring untouched - finishApply runs only on a committed
	// apply. reconcileActive restarts them once the new interfaces are up.
	if s.netmon != nil {
		s.netmon.Stop()
	}
	if s.arp != nil {
		s.arp.Stop()
	}
	if s.ggoscan != nil {
		s.ggoscan.Stop()
	}

	time.Sleep(1 * time.Second) // let the flushed interstitial bytes drain to the client

	if err := s.ReconcileApplianceState(ModeApply, plan.newProfileID); err == nil {
		if e := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); e != nil {
			log.Printf("[Apply] failed to persist ACTIVE state: %v", e)
		}
		// The new profile is live: drop the stashed prior copy of the same name.
		if plan.stashProfileID != 0 {
			if _, e := s.sqlite.Exec("DELETE FROM profiles WHERE id = ?", plan.stashProfileID); e != nil {
				log.Printf("[Apply] failed to drop stashed profile %d: %v", plan.stashProfileID, e)
			}
		}
		_ = s.sqlite.LogAudit(actor, "APPLY_PROFILE", profileName, "", "", "SUCCESS")
		log.Printf("[Apply] Profile %q applied; appliance is ACTIVE.", profileName)
		// Push the now-ACTIVE state to every connected client. The reconcile above
		// publishes while the DB still reads CONFIGURING (it runs before SetState),
		// so without this the header pill stays "Configuring" until the next full page
		// render. Mirrors finishSwitch.
		s.publishDashboard()
		return
	} else {
		log.Printf("[Apply] Profile %q failed, rolling back: %v", profileName, err)
	}

	// Failure: revert to the state the apply began in - ONBOARDING for a first
	// setup, ACTIVE when authoring an additional profile from a running box.
	revertState := plan.originState
	if revertState == "" || revertState == db.StateConfiguring {
		revertState = db.StateOnboarding
	}
	if err := s.sqlite.SetState(db.LifecycleStateKey, revertState); err != nil {
		log.Printf("[Apply] failed to revert to %s state: %v", revertState, err)
	}

	// Restore the snapshot conf and reload Kea. Best-effort, but log a failure so a
	// rollback that couldn't restore the prior config is diagnosable.
	if plan.snapPath != "" {
		if data, e := os.ReadFile(plan.snapPath); e == nil {
			live := filepath.Join(s.cfg.KeaConfDir, "kea-dhcp4.conf")
			if e := os.WriteFile(live, data, 0660); e != nil {
				log.Printf("[Apply] rollback: restore snapshot conf: %v", e)
			} else if e := s.kea.ReloadConfig(); e != nil {
				log.Printf("[Apply] rollback: Kea reload after restore: %v", e)
			}
		}
	}

	// Revert the active profile in SQLite. Best-effort, but a silent failure here is
	// how a box boots with no active profile - so log it.
	if err := s.rollbackProfileTables(plan, profileName); err != nil {
		log.Printf("[Apply] rollback: revert profile table: %v", err)
	}

	// ModeApply (not Converge) so the full NM teardown removes any connection the
	// failed forward apply created for a scope the prior profile lacks - otherwise a
	// stale interface lingers, re-IP'd onto the new profile while Kea serves the old.
	if e := s.ReconcileApplianceState(ModeApply, plan.prevProfileID); e != nil {
		log.Printf("[Apply] Rollback reconcile reported: %v", e)
	}
	_ = s.sqlite.LogAudit(actor, "APPLY_PROFILE", profileName, "", "", "FAILED")
}

// rollbackProfileTables reverts the profiles table after a failed apply, in one
// transaction: drop the failed new profile (freeing its UNIQUE name), rename the
// stashed prior copy back to its name, and re-activate the previously-active profile.
// Ordering is load-bearing - the DELETE must precede the stash rename so the name is
// free. Pure SQL (no reconcile/network), so finishApply and its test share one code
// path instead of the test re-implementing the rollback.
func (s *Server) rollbackProfileTables(plan applyPlan, profileName string) error {
	rtx, err := s.sqlite.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	_, e1 := rtx.Exec("UPDATE profiles SET active = 0")
	// Drop the failed new profile first, freeing its UNIQUE name for the stash.
	_, e2 := rtx.Exec("DELETE FROM profiles WHERE id = ?", plan.newProfileID)
	var e3 error
	if plan.stashProfileID != 0 {
		_, e3 = rtx.Exec("UPDATE profiles SET name = ? WHERE id = ?", profileName, plan.stashProfileID)
	}
	var e4 error
	if plan.prevProfileID != 0 {
		_, e4 = rtx.Exec("UPDATE profiles SET active = 1 WHERE id = ?", plan.prevProfileID)
	}
	return errors.Join(e1, e2, e3, e4, rtx.Commit())
}
