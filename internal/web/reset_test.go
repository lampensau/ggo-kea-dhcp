package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
)

func count(t *testing.T, s *Server, q string) int {
	t.Helper()
	var n int
	if err := s.sqlite.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("%q: %v", q, err)
	}
	return n
}

// TestRoutineResetDB verifies the routine reset deactivates the profile and returns to
// ONBOARDING while KEEPING the profile library and port labels (a new job re-pins to
// labelled ports). The MariaDB host-store purge is best-effort (nil here) and verified
// live - this covers the SQLite side.
func TestRoutineResetDB(t *testing.T) {
	s, _ := newTestServer(t)
	_, _ = s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('venue', 1)")
	_, _ = s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES ('00aa', 'Camera 1')")
	_ = s.sqlite.SetStates(map[string]string{"uplink_ssid": "VenueWiFi", "uplink_pass": "secret123", "uplink_enabled": "1"})
	_ = s.sqlite.SetState(dhcpStandDownKey, "1")
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)

	if err := s.routineResetDB(); err != nil {
		t.Fatalf("routineResetDB: %v", err)
	}

	// The box-level WiFi uplink must be cleared - in ONBOARDING wlan0 is the SoftAP, so
	// stale uplink creds can't apply and must not prefill the setup wizard.
	if v, _ := s.sqlite.GetState("uplink_ssid"); v != "" {
		t.Errorf("routine reset must clear the WiFi uplink, got ssid %q", v)
	}
	// A stale stand-down would render the holdoff on the next job's apply - ACTIVE but
	// serving nothing. A reset is a clean slate; the flag must be gone.
	if s.dhcpStoodDown() {
		t.Error("routine reset must clear the DHCP stand-down flag")
	}

	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateOnboarding {
		t.Errorf("lifecycle = %q, want %q", st, db.StateOnboarding)
	}
	if active := count(t, s, "SELECT COUNT(*) FROM profiles WHERE active = 1"); active != 0 {
		t.Errorf("profile still active after routine reset: %d", active)
	}
	if profiles := count(t, s, "SELECT COUNT(*) FROM profiles"); profiles != 1 {
		t.Errorf("routine reset must keep the profile library, got %d profiles", profiles)
	}
	if labels := count(t, s, "SELECT COUNT(*) FROM port_labels"); labels != 1 {
		t.Errorf("routine reset must keep port labels, got %d", labels)
	}
}

// TestResetClearsUpdateState proves both reset paths drop the self-update
// record. A leftover update_latest_* would light the footer badge in ONBOARDING
// with a dead /settings#update anchor (the update card is ACTIVE-gated).
func TestResetClearsUpdateState(t *testing.T) {
	seed := func(s *Server) {
		_ = s.sqlite.SetStates(map[string]string{
			stateUpdateVersion:       "9.9.9",
			stateUpdateSHA256:        "deadbeef",
			stateUpdateNotified:      "9.9.9",
			stateUpdateBackoffUntil:  "2099-01-01T00:00:00Z",
			"update_applied_version": "9.9.9",
		})
	}
	assertCleared := func(t *testing.T, s *Server) {
		t.Helper()
		if n := count(t, s, "SELECT COUNT(*) FROM app_state WHERE key LIKE 'update\\_%' ESCAPE '\\'"); n != 0 {
			t.Errorf("reset left %d update_* app_state row(s)", n)
		}
	}

	t.Run("routine", func(t *testing.T) {
		s, _ := newTestServer(t)
		seed(s)
		_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)
		if err := s.routineResetDB(); err != nil {
			t.Fatalf("routineResetDB: %v", err)
		}
		assertCleared(t, s)
	})

	t.Run("factory", func(t *testing.T) {
		s, _ := newTestServer(t)
		seed(s)
		_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)
		if err := s.factoryWipeDB(); err != nil {
			t.Fatalf("factoryWipeDB: %v", err)
		}
		assertCleared(t, s)
	})
}

// TestFactoryWipeDB verifies the factory reset wipes the admin, profiles, scopes, and
// port labels, and drops to FACTORY.
func TestFactoryWipeDB(t *testing.T) {
	s, _ := newTestServer(t)
	_, _ = s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('venue', 1)")
	_, _ = s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES ('00aa', 'Camera 1')")
	_, _ = s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES ('admin', 'x')")
	_ = s.sqlite.SetStates(map[string]string{"uplink_ssid": "VenueWiFi", "uplink_pass": "secret123", "uplink_enabled": "1"})
	_ = s.sqlite.SetState("lease_lifetime", "7200")
	_ = s.sqlite.SetState(dhcpStandDownKey, "1")
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)

	if err := s.factoryWipeDB(); err != nil {
		t.Fatalf("factoryWipeDB: %v", err)
	}

	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateFactory {
		t.Errorf("lifecycle = %q, want %q", st, db.StateFactory)
	}
	if v, _ := s.sqlite.GetState("uplink_ssid"); v != "" {
		t.Errorf("factory reset must clear the WiFi uplink, got ssid %q", v)
	}
	// #133: lease_lifetime is a box-level DHCP default and must not survive a factory
	// reset (it did until this fix - the wipe set matches the backup whitelist now).
	if v, _ := s.sqlite.GetState("lease_lifetime"); v != "" {
		t.Errorf("factory reset must clear lease_lifetime, got %q", v)
	}
	if s.dhcpStoodDown() {
		t.Error("factory reset must clear the DHCP stand-down flag")
	}
	for _, tbl := range []string{"profiles", "scopes", "port_labels", "users"} {
		if n := count(t, s, "SELECT COUNT(*) FROM "+tbl); n != 0 {
			t.Errorf("factory reset left %d row(s) in %s", n, tbl)
		}
	}
}

// TestFactoryWipeDBAllOrNothing proves the wipe and the FACTORY state flip commit
// as one transaction: when any statement fails, NOTHING is wiped - the failure
// mode this prevents is a box with zero admins whose lifecycle still demands
// login (a UI lockout only manual DB surgery could undo).
func TestFactoryWipeDBAllOrNothing(t *testing.T) {
	s, _ := newTestServer(t)
	_, _ = s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES ('admin', 'x')")
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)

	// Force a mid-wipe failure: one of the wiped tables is gone.
	if _, err := s.sqlite.Exec("DROP TABLE port_labels"); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	if err := s.factoryWipeDB(); err == nil {
		t.Fatal("factoryWipeDB should report the failed statement")
	}
	if n := count(t, s, "SELECT COUNT(*) FROM users"); n != 1 {
		t.Errorf("a failed wipe deleted the admin (users=%d) - the tx did not roll back", n)
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateActive {
		t.Errorf("a failed wipe changed the lifecycle to %q - the tx did not roll back", st)
	}
}
