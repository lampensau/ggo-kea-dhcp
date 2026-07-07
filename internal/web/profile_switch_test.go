package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestFailedSwitchRestoresPrevProfile drives finishSwitch's REAL rollback (the
// rollbackFailed tail shared with finishApply): the test server's Kea endpoint is
// unreachable, so the forward reconcile fails and the rollback must re-activate
// the previous profile, return the lifecycle to ACTIVE, and audit the failure.
func TestFailedSwitchRestoresPrevProfile(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	seed := func(name string, active int) int {
		res, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES (?, ?)", name, active)
		if err != nil {
			t.Fatalf("seed profile %s: %v", name, err)
		}
		id, _ := res.LastInsertId()
		if _, err := s.sqlite.Exec(
			`INSERT INTO scopes (profile_id, vlan_id, cidr, preset, pool_spec, uplink_json)
			 VALUES (?, 0, '10.0.0.0/24', 'generic', '{}', '{}')`, id); err != nil {
			t.Fatalf("seed scope for %s: %v", name, err)
		}
		return int(id)
	}
	prevID := seed("running", 1)
	targetID := seed("candidate", 0)

	plan, err := s.beginSwitch(targetID)
	if err != nil {
		t.Fatalf("beginSwitch: %v", err)
	}
	s.finishSwitch(plan, "test")

	var activeID int
	if err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1").Scan(&activeID); err != nil {
		t.Fatalf("post-rollback no active profile: %v", err)
	}
	if activeID != prevID {
		t.Fatalf("post-rollback active profile = %d, want the previous %d", activeID, prevID)
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateActive {
		t.Fatalf("post-rollback state = %q, want ACTIVE", st)
	}
	var n int
	if err := s.sqlite.QueryRow(
		"SELECT COUNT(*) FROM audit_log WHERE action = 'SWITCH_PROFILE' AND result = 'FAILED'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("SWITCH_PROFILE FAILED audit rows = %d (err=%v), want 1", n, err)
	}
}
