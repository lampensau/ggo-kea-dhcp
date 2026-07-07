package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestCoerceRestoredLifecycle pins the mapping: a configured box (ACTIVE, or the
// transient CONFIGURING a mid-apply backup can capture) restores ACTIVE; everything
// else - empty, FACTORY, or a corrupt/hand-edited string - falls to the ONBOARDING
// safe floor.
func TestCoerceRestoredLifecycle(t *testing.T) {
	cases := map[string]string{
		db.StateActive:      db.StateActive,
		db.StateConfiguring: db.StateActive,
		db.StateOnboarding:  db.StateOnboarding,
		"":                  db.StateOnboarding,
		db.StateFactory:     db.StateOnboarding,
		"ACTIVE ":           db.StateOnboarding, // trailing space = not a known state
		"garbage":           db.StateOnboarding,
	}
	for in, want := range cases {
		if got := coerceRestoredLifecycle(in); got != want {
			t.Errorf("coerceRestoredLifecycle(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRestoreCoercesConfiguringToActive proves a backup captured mid-apply (lifecycle
// CONFIGURING) restores to ACTIVE, not the transient state - otherwise the box would
// serve DHCP but sit on the "Configuring" badge with self-update disabled until reboot.
func TestRestoreCoercesConfiguringToActive(t *testing.T) {
	s, _ := newTestServer(t)
	var schema int
	_ = s.sqlite.QueryRow("PRAGMA user_version;").Scan(&schema)
	b := &Backup{
		Format: backupFormat, AppSchema: schema, Lifecycle: db.StateConfiguring,
		Profiles: []BackupProfile{{Name: "Live", Active: true}},
	}
	lifecycle, err := s.restore(b, map[string]bool{"profiles": true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if lifecycle != db.StateActive {
		t.Errorf("restore returned lifecycle %q, want ACTIVE", lifecycle)
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateActive {
		t.Errorf("persisted lifecycle = %q, want ACTIVE", st)
	}
}

// The router half of #126 (an unknown lifecycle string must fail closed rather than
// serve every route) is covered where the other stateRedirectFor cases live, in
// TestStateRedirectFor_Extra (routing_test.go).
