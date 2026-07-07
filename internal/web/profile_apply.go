package web

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

// reservedProfileName matches the ".stash-<n>" shape persistProfile uses to park a
// same-named profile aside. listProfiles hides it (GLOB '*.stash-[0-9]*') and
// sweepOrphanedStashes deletes it, so an operator profile saved under that form would
// disappear from the UI and later be swept with its scopes - reject it.
var reservedProfileName = regexp.MustCompile(`\.stash-[0-9]`)

// validateProfileName rejects an empty name and the reserved stash shape.
func validateProfileName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("Profile name cannot be empty.")
	}
	if reservedProfileName.MatchString(name) {
		return fmt.Errorf(`Profile name may not contain the reserved ".stash-<number>" form.`)
	}
	return nil
}

// validateScopeTopology rejects a multi-scope profile whose interface topology is
// self-contradictory in ways kea -t does not catch, so the box can't reach ACTIVE
// and then silently misbehave. Two failure modes, both confirmed to pass RenderProfile
// + TestConfig today:
//
//   - Duplicate VLAN ID: reconcileActive configures one eth0.<vid> per scope, so a
//     second scope on the same VLAN just reconfigures that interface with its own
//     gateway - one whole segment never serves, with no error surfaced. VlanID 0 is
//     "untagged on eth0"; only one scope may hold it, so this also enforces the
//     single-untagged rule (the wizard's parse-time check is now a UI-facing backstop).
//   - Overlapping CIDRs: subnetIDForIP/subnetMatcherForScopes key a subnet by the
//     FIRST scope whose CIDR contains an IP, so an address inside an overlap is filed
//     under the wrong subnet-id and its reservation is permanently dead.
//
// Checked at both apply choke points (beginApply from the wizard form, beginSwitch
// from a stored profile) so an import/restore that introduced a bad topology is caught
// on its next apply, not just at wizard time.
func validateScopeTopology(scopes []ScopeConfig) error {
	seenVLAN := map[int]bool{}
	prevNets := make([]*net.IPNet, 0, len(scopes))
	for _, sc := range scopes {
		// Range-check here too, not just at wizard parse time: beginSwitch loads scopes
		// from a stored profile (import/restore) that never went through parseSetupScopes.
		if !validVLANID(sc.VlanID) {
			return fmt.Errorf("Scope VLAN ID %d is out of range (0-4094).", sc.VlanID)
		}
		if seenVLAN[sc.VlanID] {
			if sc.VlanID == 0 {
				return fmt.Errorf("Only one untagged network scope is allowed on eth0. All other scopes must specify a VLAN ID.")
			}
			return fmt.Errorf("VLAN %d is used by more than one scope. Give each scope a distinct VLAN ID.", sc.VlanID)
		}
		seenVLAN[sc.VlanID] = true

		_, ipnet, err := net.ParseCIDR(sc.CIDR)
		if err != nil {
			return fmt.Errorf("Scope subnet %q is not a valid CIDR: %w", sc.CIDR, err)
		}
		// ponytail: O(n²) pairwise overlap. n is a handful of scopes (the wizard caps
		// them), so a sort/interval-tree would be more code for no measurable gain.
		for _, prev := range prevNets {
			if prev.Contains(ipnet.IP) || ipnet.Contains(prev.IP) {
				return fmt.Errorf("Scope subnets %s and %s overlap. Each scope needs a distinct subnet.", prev.String(), ipnet.String())
			}
		}
		prevNets = append(prevNets, ipnet)
	}
	return nil
}

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
	// prevUplink holds the box-level uplink app_state keys as they were before
	// beginApply overwrote them, so a failed apply can restore them - the rollback
	// reconcile reads these keys to reconnect wlan0.
	prevUplink map[string]string
}

// prepareReconcile runs the irreversible preamble shared by beginApply and beginSwitch:
// render the candidate config from renderScopes, validate it (kea -t), refuse if a
// self-update holds the guard, claim the shared mutation guard, and snapshot the live
// config under snapLabel. On success it returns the snapshot path WITH THE GUARD HELD -
// the caller owns endReconcile on any later failure. On failure it holds nothing.
//
// Ordering is load-bearing: validate BEFORE claiming the guard, so a doomed candidate
// never locks the control plane and a busy guard never masks the real validation error
// (TestBeginApplyValidatesBeforeClaimingGuard pins this). The guard is claimed before any
// persistent artifact so every irreversible step is serialized by one apply/switch.
func (s *Server) prepareReconcile(renderScopes []kea.ScopeInput, snapLabel string) (string, error) {
	in := s.baseRenderInput()
	in.Scopes = renderScopes
	// Validate on "*": a scope's eth0.<vid> interface isn't created until the reconcile,
	// so a per-interface kea -t here would wrongly fail "interface doesn't exist"; the
	// reconcile re-validates the real per-interface config once the interfaces are up.
	in.IfaceWildcard = true
	configStr, _, err := kea.RenderProfile(in)
	if err != nil {
		return "", fmt.Errorf("Failed to generate the Kea configuration: %w", err)
	}
	if err := kea.TestConfig(configStr); err != nil {
		return "", fmt.Errorf("The generated configuration failed validation (kea-dhcp4 -t): %w", err)
	}
	// A running self-update holds the same guard; name it explicitly rather than let the
	// guard-busy message below lie about "another profile change".
	if s.updating.Load() {
		return "", fmt.Errorf("A software update is in progress - try again once it completes.")
	}
	if !s.beginReconcile() {
		return "", fmt.Errorf("Another profile change is already in progress.")
	}
	snapPath, err := s.snapshotKeaConf(snapLabel)
	if err != nil {
		s.endReconcile()
		return "", fmt.Errorf("Failed to snapshot the current configuration: %w", err)
	}
	return snapPath, nil
}

// beginApply is the synchronous half of a profile apply: it renders + validates
// the candidate Kea config, snapshots the current one, persists the new
// profile/scopes, and transitions the appliance to the persisted CONFIGURING
// state - all BEFORE the caller flushes the reconnect interstitial. Entering
// CONFIGURING synchronously is what stops the interstitial's /dashboard probe
// from bouncing back to /setup (routing treats CONFIGURING like ACTIVE), and
// makes a crash before finishApply recoverable on boot. On any error it leaves
// the appliance untouched (state still ONBOARDING, uplink credentials restored,
// apply guard cleared).
func (s *Server) beginApply(profileName string, scopes []ScopeConfig, uplink UplinkConfig) (applyPlan, error) {
	if err := validateProfileName(profileName); err != nil {
		return applyPlan{}, err
	}
	if err := validateScopeTopology(scopes); err != nil {
		return applyPlan{}, err
	}
	renderScopes, gatewayIP := buildRenderScopes(scopes, uplink.Enabled)

	// Render + validate + claim the guard + snapshot, guard held on success.
	snapPath, err := s.prepareReconcile(renderScopes, "pre-apply")
	if err != nil {
		return applyPlan{}, err
	}

	// Capture the current box-level uplink for finishApply's failure restore, now that
	// the guard is held. A read error aborts the apply: proceeding would capture "" and a
	// later rollback would then "restore" empty credentials over the real ones - only the
	// snapshot has been written so far, so aborting here leaves the box untouched.
	prevUplink := make(map[string]string, len(uplinkStateKeys))
	for _, k := range uplinkStateKeys {
		v, err := s.sqlite.GetState(k)
		if err != nil {
			s.endReconcile()
			return applyPlan{}, fmt.Errorf("Failed to read the current WiFi uplink for rollback: %w", err)
		}
		prevUplink[k] = v
	}

	plan := applyPlan{snapPath: snapPath, gatewayIP: gatewayIP, prevUplink: prevUplink}
	plan.originState, _ = s.sqlite.GetState(db.LifecycleStateKey)
	_ = s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&plan.prevProfileID)

	// persistProfile writes the profile, its scopes, AND the CONFIGURING state in one
	// transaction (synchronously, before the interstitial is flushed - this is what
	// keeps the interstitial's /dashboard nav from bouncing back to /setup).
	if err := s.persistProfile(profileName, scopes, uplink, &plan); err != nil {
		s.endReconcile()
		return applyPlan{}, err
	}
	return plan, nil
}

// uplinkStateKeys / uplinkState are the single definition of the box-level WiFi
// uplink app_state keys: the rollback capture iterates the keys and every writer
// builds its map through uplinkState, so the two cannot drift apart.
var uplinkStateKeys = []string{"uplink_enabled", "uplink_ssid", "uplink_pass"}

func uplinkState(enabled bool, ssid, pass string) map[string]string {
	en := "0"
	if enabled {
		en = "1"
	}
	return map[string]string{uplinkStateKeys[0]: en, uplinkStateKeys[1]: ssid, uplinkStateKeys[2]: pass}
}

// restoreUplinkState puts the pre-apply box-level uplink keys back after a failed
// apply, so the rollback reconcile reconnects wlan0 to the prior uplink instead of
// the failed profile's. Log-on-error like the other best-effort rollback steps.
func (s *Server) restoreUplinkState(prev map[string]string) {
	if len(prev) == 0 {
		return
	}
	if err := s.sqlite.SetStates(prev); err != nil {
		log.Printf("[Apply] rollback: restore uplink credentials: %v", err)
	}
}

// persistProfile writes the new (active) profile, its scopes, AND the box-level
// WiFi uplink in one transaction, setting plan.newProfileID. A pre-existing
// same-named profile is renamed aside and deactivated (not deleted), recorded in
// plan.stashProfileID, so a failed apply can restore the operator's prior config -
// re-applying the active profile's own name must not destroy it before the apply
// is known good. finishApply drops the stash on success; the failure path renames
// it back. The uplink rides the same transaction so an earlier failure (render,
// validate, snapshot) or a rolled-back commit never wrote it at all - only
// finishApply's failure branch needs an explicit restore (restoreUplinkState).
func (s *Server) persistProfile(profileName string, scopes []ScopeConfig, uplink UplinkConfig, plan *applyPlan) error {
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
	// Deactivate is load-bearing: a silent failure here would leave the prior profile
	// active alongside the new one (two active rows). Check it like the INSERT below.
	if _, err := tx.Exec("UPDATE profiles SET active = 0"); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("Failed to deactivate current profile: %w", err)
	}
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
			INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset, pool_spec, uplink_json, pool_plan, services_json, name)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			plan.newProfileID, ifaceMode, sc.VlanID, sc.CIDR, sc.Preset, poolSpec, uplinkSpec, planJSON, servicesSpec, sc.Name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("Failed to store scope: %w", err)
		}
	}
	// The box-level WiFi uplink (one wlan0) lands in the same transaction; the
	// finishApply reconcile reads it back to configure the uplink.
	for k, v := range uplinkState(uplink.Enabled, uplink.SSID, uplink.Password) {
		if _, err := tx.Exec(`
			INSERT INTO app_state (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("Failed to store WiFi uplink: %w", err)
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

	// Tear down the prior profile's monitors and DNS before the imminent re-IP.
	// Done here (not in beginApply) so a beginApply that fails validation/snapshot
	// leaves an ACTIVE box's monitoring untouched - finishApply runs only on a
	// committed apply. reconcileActive restarts everything once the new interfaces
	// are up.
	s.stopActiveMonitors()

	time.Sleep(1 * time.Second) // let the flushed interstitial bytes drain to the client

	if err := s.ReconcileApplianceState(ModeApply, plan.newProfileID); err == nil {
		s.setActiveAudited("APPLY_PROFILE", profileName)
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
	s.rollbackFailed(rollbackSpec{
		tag:           "Apply",
		action:        "APPLY_PROFILE",
		profileName:   profileName,
		actor:         actor,
		revertState:   revertState,
		prevProfileID: plan.prevProfileID,
		snapPath:      plan.snapPath,
		revertTables:  func() error { return s.rollbackProfileTables(plan, profileName) },
		// Restore the pre-apply uplink credentials BEFORE the rollback reconcile,
		// which reads them from app_state to reconnect wlan0.
		preReconcile: func() { s.restoreUplinkState(plan.prevUplink) },
	})
}

// rollbackSpec parameterizes rollbackFailed with the per-flavor pieces of a failed
// apply/switch: what to call it, which state to revert to, which profile to
// reconcile back to, and how to revert the profile tables.
type rollbackSpec struct {
	tag           string // log prefix: "Apply" / "Switch"
	action        string // audit action: APPLY_PROFILE / SWITCH_PROFILE
	profileName   string
	actor         string
	revertState   string // lifecycle state to persist before the rollback reconcile
	prevProfileID int
	snapPath      string
	revertTables  func() error // SQL revert of the profiles/scopes tables
	preReconcile  func()       // optional extra restore step before the reconcile
}

// rollbackFailed is the one failure tail shared by finishApply and finishSwitch:
// revert the profile tables, restore the snapshot conf + reload Kea, persist the
// revert lifecycle state, run any flavor-specific restore, reconcile back to the
// previous profile, and audit. Every step is best-effort-but-logged - a rollback
// must attempt all of them even when one fails, and a silent skip is how a box
// boots with no active profile.
func (s *Server) rollbackFailed(p rollbackSpec) {
	// Ordering: tables first, then the snapshot conf, then the lifecycle state.
	// A crash mid-rollback therefore leaves the state at CONFIGURING with the
	// tables already reverted, and the boot resume completes the PREVIOUS
	// profile (or falls back to onboarding when there is none) - reverting the
	// state first would instead let a crash strand the failed profile's rows
	// under a final state.
	if err := p.revertTables(); err != nil {
		log.Printf("[%s] rollback: revert profile table: %v", p.tag, err)
	}

	// Restore the snapshot conf and reload Kea.
	if p.snapPath != "" {
		if data, e := os.ReadFile(p.snapPath); e == nil {
			live := filepath.Join(s.cfg.KeaConfDir, "kea-dhcp4.conf")
			if e := writeFileSync(live, data, 0660); e != nil {
				log.Printf("[%s] rollback: restore snapshot conf: %v", p.tag, e)
			} else if e := s.kea.ReloadConfig(context.Background()); e != nil {
				log.Printf("[%s] rollback: Kea reload after restore: %v", p.tag, e)
			}
		}
	}

	// Persist the revert state before reconciling so the reconcile dispatches for
	// that state (ACTIVE for a switch, the origin state for an apply).
	if err := s.sqlite.SetState(db.LifecycleStateKey, p.revertState); err != nil {
		log.Printf("[%s] failed to revert to %s state: %v", p.tag, p.revertState, err)
	}

	if p.preReconcile != nil {
		p.preReconcile()
	}

	// ModeApply (not Converge) so the full NM teardown removes any connection the
	// failed forward apply/switch created for a scope the prior profile lacks -
	// otherwise a stale interface lingers, its addressing diverging from the
	// served subnets.
	if e := s.ReconcileApplianceState(ModeApply, p.prevProfileID); e != nil {
		// The apply/switch failed AND the recovery failed: the box is genuinely
		// half-configured, which the plain FAILED row below doesn't convey.
		log.Printf("[%s] Rollback reconcile reported: %v", p.tag, e)
		_ = s.sqlite.LogAudit("SYSTEM", "ROLLBACK_FAILED", p.profileName, "", e.Error(), "ERROR")
	}
	_ = s.sqlite.LogAudit(p.actor, p.action, p.profileName, "", "", "FAILED")
}

// setActiveAudited persists the ACTIVE lifecycle after a successful apply/switch
// reconcile, retrying once (a transient SQLITE_BUSY is the plausible failure) and
// auditing a persistent one: DHCP is serving but the UI would sit on the
// CONFIGURING interstitial until a reboot finalizes the state, so the operator
// must at least see why.
func (s *Server) setActiveAudited(action, target string) {
	// busy_timeout=5000 already absorbs lock contention, so a bare immediate re-call
	// bought nothing; a genuine failure here is a real DB error, audited below.
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		log.Printf("[%s] failed to persist ACTIVE state: %v", action, err)
		_ = s.sqlite.LogAudit("SYSTEM", action, target, "",
			"DHCP is serving but the ACTIVE state could not be persisted - the UI stays on Configuring until a reboot: "+err.Error(), "ERROR")
	}
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
	// All-or-nothing: committing a partial revert (e.g. the DELETE landed but the
	// stash rename didn't) would strand the prior profile under its stash name.
	// Rollback is a no-op after a successful Commit.
	defer func() { _ = rtx.Rollback() }()
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
	if err := errors.Join(e1, e2, e3, e4); err != nil {
		return err
	}
	return rtx.Commit()
}
