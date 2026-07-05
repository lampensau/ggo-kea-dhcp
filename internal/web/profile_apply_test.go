package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestPersistProfileEntersConfiguringAtomically proves persistProfile writes the
// CONFIGURING lifecycle state INSIDE the same transaction as the profile/scope rows
// (the fix preventing a committed-but-unreconciled profile if the state write were a
// separate statement that failed). Starts from ONBOARDING so the transition is real.
func TestPersistProfileEntersConfiguringAtomically(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	var plan applyPlan
	scopes := []ScopeConfig{{CIDR: "10.0.0.0/24", Preset: "greengo"}}
	if err := s.persistProfile("beta", scopes, &plan); err != nil {
		t.Fatalf("persistProfile: %v", err)
	}
	if plan.newProfileID == 0 {
		t.Fatalf("newProfileID not set")
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateConfiguring {
		t.Fatalf("lifecycle state = %q, want CONFIGURING (persistProfile must enter it in-tx)", st)
	}
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM profiles WHERE id = ? AND active = 1", plan.newProfileID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("new active profile missing alongside the state write (n=%d err=%v)", n, err)
	}
}

// TestPersistProfileStashesSameName proves that re-applying a profile whose name
// matches the currently-active profile does NOT delete the prior profile (and its
// CASCADE-linked scopes) outright: it stashes the row aside so a failed apply can
// roll back to it. The pre-fix DELETE left prevProfileID dangling and could leave
// the box with no active profile after a rollback.
func TestPersistProfileStashesSameName(t *testing.T) {
	s, _ := newTestServer(t)

	// Seed an active profile "alpha" (id 1) with one scope.
	res, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('alpha', 1)")
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	prevID, _ := res.LastInsertId()
	if _, err := s.sqlite.Exec(
		"INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset) VALUES (?, 'physical', 0, '10.0.0.0/24', 'greengo')",
		prevID); err != nil {
		t.Fatalf("seed scope: %v", err)
	}

	// Re-apply the SAME name (an in-place edit of the active profile).
	var plan applyPlan
	plan.prevProfileID = int(prevID)
	scopes := []ScopeConfig{{CIDR: "10.0.0.0/24", Preset: "greengo"}}
	if err := s.persistProfile("alpha", scopes, &plan); err != nil {
		t.Fatalf("persistProfile: %v", err)
	}

	// The prior profile must be stashed (recorded, still present, deactivated),
	// not deleted - its scopes must survive for a rollback.
	if plan.stashProfileID != int(prevID) {
		t.Fatalf("stashProfileID = %d, want %d", plan.stashProfileID, prevID)
	}
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM profiles WHERE id = ?", prevID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("prior profile row gone (n=%d err=%v); rollback impossible", n, err)
	}
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM scopes WHERE profile_id = ?", prevID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("prior scopes CASCADE-dropped (n=%d err=%v)", n, err)
	}
	// The new profile is the active one, under the operator's name.
	var activeName string
	var activeID int
	if err := s.sqlite.QueryRow("SELECT id, name FROM profiles WHERE active = 1").Scan(&activeID, &activeName); err != nil {
		t.Fatalf("no active profile: %v", err)
	}
	if activeName != "alpha" || activeID == int(prevID) {
		t.Fatalf("active profile = (%d,%q), want a new id named alpha", activeID, activeName)
	}

	// Drive finishApply's REAL rollback (the shared helper, not a re-typed copy) and
	// assert the prior profile is restored: the failed new profile is dropped, the
	// stash is renamed back, and the previously-active profile is re-activated.
	if err := s.rollbackProfileTables(plan, "alpha"); err != nil {
		t.Fatalf("rollbackProfileTables: %v", err)
	}
	if err := s.sqlite.QueryRow("SELECT id, name FROM profiles WHERE active = 1").Scan(&activeID, &activeName); err != nil {
		t.Fatalf("post-rollback no active profile: %v", err)
	}
	if activeID != int(prevID) || activeName != "alpha" {
		t.Fatalf("post-rollback active = (%d,%q), want (%d,alpha)", activeID, activeName, prevID)
	}
	// The failed new profile must be gone, and exactly one profile named "alpha" remains.
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM profiles WHERE id = ?", plan.newProfileID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed new profile survived rollback (n=%d err=%v)", n, err)
	}
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM profiles WHERE name = 'alpha'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("want exactly one profile named alpha after rollback (n=%d err=%v)", n, err)
	}
}

// TestFailedApplyRestoresUplink proves a failed apply restores the box-level WiFi
// uplink credentials it wrote mid-apply: beginApply persists the NEW uplink before
// the profile commit (the reconcile reads it from app_state), so finishApply's
// rollback must put the prior credentials back - otherwise the rollback reconcile
// reconnects wlan0 to the failed profile's uplink.
func TestFailedApplyRestoresUplink(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	prior := map[string]string{"uplink_enabled": "1", "uplink_ssid": "old-net", "uplink_pass": "old-pass"}
	if err := s.sqlite.SetStates(prior); err != nil {
		t.Fatalf("seed uplink: %v", err)
	}

	scopes := []ScopeConfig{{CIDR: "10.0.0.0/24", Preset: "generic"}}
	scopes[0].Plan = seedDefaultPlan(scopes[0])
	plan, err := s.beginApply("beta", scopes, UplinkConfig{Enabled: true, SSID: "new-net", Password: "new-pass"})
	if err != nil {
		t.Fatalf("beginApply: %v", err)
	}
	// Mid-apply the new credentials must be persisted (the reconcile reads them).
	if ssid, _ := s.sqlite.GetState("uplink_ssid"); ssid != "new-net" {
		t.Fatalf("mid-apply uplink_ssid = %q, want new-net", ssid)
	}

	// The test server's Kea endpoint is unreachable, so the ModeApply reconcile
	// fails and finishApply takes its rollback path.
	s.finishApply(plan, "beta", "test")

	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateOnboarding {
		t.Fatalf("post-rollback state = %q, want ONBOARDING", st)
	}
	for k, want := range prior {
		if got, _ := s.sqlite.GetState(k); got != want {
			t.Errorf("%s = %q after failed apply, want %q", k, got, want)
		}
	}
}

// TestSweepOrphanedStashes proves the boot-time stash sweep (run by
// resumeInterruptedApply after a crash-interrupted apply completes) deletes only
// rollback stashes - "<name>.stash-<id>", active = 0 - and never a real or active
// profile.
func TestSweepOrphanedStashes(t *testing.T) {
	s, _ := newTestServer(t)
	seed := []struct {
		name   string
		active int
	}{
		{"Live", 1},            // real, active
		{"Backup", 0},          // real, inactive
		{"Live.stash-3", 0},    // orphaned stash -> swept
		{"Other.stash-128", 0}, // orphaned stash -> swept
		{"weird.stash-9", 1},   // active=0 guard: an (impossible) active stash is NOT swept
	}
	for _, p := range seed {
		if _, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES (?, ?)", p.name, p.active); err != nil {
			t.Fatalf("seed %s: %v", p.name, err)
		}
	}

	if err := s.sweepOrphanedStashes(); err != nil {
		t.Fatalf("sweepOrphanedStashes: %v", err)
	}

	rows, err := s.sqlite.Query("SELECT name FROM profiles ORDER BY name")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, n)
	}
	rows.Close()

	want := map[string]bool{"Live": true, "Backup": true, "weird.stash-9": true}
	if len(got) != len(want) {
		t.Fatalf("after sweep have %v, want exactly %v (inactive stashes gone, active kept)", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("profile %q should have been swept (or wrongly removed)", n)
		}
	}
}
