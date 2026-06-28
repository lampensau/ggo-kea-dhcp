package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestRestoreClearsSessions proves a full-stack restore wipes the sessions table:
// the restored admin set may not include the currently-logged-in user, so a stale
// ggo_session must not outlive its account.
func TestRestoreClearsSessions(t *testing.T) {
	s, _ := newTestServer(t)
	if _, err := s.sqlite.Exec("INSERT INTO users (username, password_hash) VALUES ('admin','h')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('p', 1)"); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	b, err := s.buildBackup()
	if err != nil {
		t.Fatalf("buildBackup: %v", err)
	}
	// A live session that must not survive the restore.
	if _, err := s.sqlite.Exec(
		"INSERT INTO sessions (session_id, username, csrf_token, expires_at) VALUES ('sid','admin','csrf', datetime('now','+1 hour'))"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := s.restore(b, allSel()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 0 {
		t.Fatalf("sessions survived restore (n=%d); a stale session outlived its admin", n)
	}
}
