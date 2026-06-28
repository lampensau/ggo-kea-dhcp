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
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)

	if err := s.routineResetDB(); err != nil {
		t.Fatalf("routineResetDB: %v", err)
	}

	// The box-level WiFi uplink must be cleared - in ONBOARDING wlan0 is the SoftAP, so
	// stale uplink creds can't apply and must not prefill the setup wizard.
	if v, _ := s.sqlite.GetState("uplink_ssid"); v != "" {
		t.Errorf("routine reset must clear the WiFi uplink, got ssid %q", v)
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

// TestFactoryWipeDB verifies the factory reset wipes the admin, profiles, scopes, and
// port labels, and drops to FACTORY.
func TestFactoryWipeDB(t *testing.T) {
	s, _ := newTestServer(t)
	_, _ = s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('venue', 1)")
	_, _ = s.sqlite.Exec("INSERT INTO port_labels (flex_id_hex, label) VALUES ('00aa', 'Camera 1')")
	_, _ = s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES ('admin', 'x')")
	_ = s.sqlite.SetStates(map[string]string{"uplink_ssid": "VenueWiFi", "uplink_pass": "secret123", "uplink_enabled": "1"})
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
	for _, tbl := range []string{"profiles", "scopes", "port_labels", "users"} {
		if n := count(t, s, "SELECT COUNT(*) FROM "+tbl); n != 0 {
			t.Errorf("factory reset left %d row(s) in %s", n, tbl)
		}
	}
}
