package web

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func countRows(t *testing.T, s *Server, table string) int {
	t.Helper()
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// pruneSnapshots must keep the newest snapshotKeepCount rows and delete the
// older rows AND their files.
func TestPruneSnapshotsKeepsNewestN(t *testing.T) {
	s, _ := newTestServer(t)
	dir := t.TempDir()
	s.cfg.SnapshotDir = dir

	total := snapshotKeepCount + 5
	paths := make([]string, total)
	for i := 0; i < total; i++ {
		p := filepath.Join(dir, "kea-dhcp4."+strconv.Itoa(i)+".conf")
		if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.sqlite.Exec("INSERT INTO config_snapshots (reason, path) VALUES ('test', ?)", p); err != nil {
			t.Fatal(err)
		}
		paths[i] = p
	}

	s.pruneSnapshots()

	if n := countRows(t, s, "config_snapshots"); n != snapshotKeepCount {
		t.Errorf("rows after prune = %d, want %d", n, snapshotKeepCount)
	}
	for i, p := range paths {
		_, err := os.Stat(p)
		if i < 5 && !os.IsNotExist(err) {
			t.Errorf("old snapshot file %s should be removed", p)
		}
		if i >= 5 && err != nil {
			t.Errorf("kept snapshot file %s should exist: %v", p, err)
		}
	}

	// Idempotent: a second pass under the cap deletes nothing.
	s.pruneSnapshots()
	if n := countRows(t, s, "config_snapshots"); n != snapshotKeepCount {
		t.Errorf("rows after second prune = %d, want %d", n, snapshotKeepCount)
	}
}

// pruneAuditLog must drop rows past the age window and enforce the row-count
// backstop, keeping the newest.
func TestPruneAuditLogAgeAndCount(t *testing.T) {
	s, _ := newTestServer(t)

	// Three ancient rows, three fresh ones.
	for i := 0; i < 3; i++ {
		if _, err := s.sqlite.Exec(
			"INSERT INTO audit_log (ts, actor, action, target, result) VALUES (datetime('now', '-100 days'), 'X', 'OLD', 't', 'OK')"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := s.sqlite.Exec(
			"INSERT INTO audit_log (actor, action, target, result) VALUES ('X', 'FRESH', 't', 'OK')"); err != nil {
			t.Fatal(err)
		}
	}

	s.pruneAuditLog()

	var old, fresh int
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'OLD'").Scan(&old)
	_ = s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'FRESH'").Scan(&fresh)
	if old != 0 || fresh != 3 {
		t.Errorf("after age prune: old=%d fresh=%d, want 0/3", old, fresh)
	}

	// Row-count backstop: flood past the cap, the newest auditKeepRows survive.
	if _, err := s.sqlite.Exec(`
		INSERT INTO audit_log (actor, action, target, result)
		SELECT 'X', 'FLOOD', 't', 'OK'
		FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < ?) SELECT x FROM c)`,
		auditKeepRows+50); err != nil {
		t.Fatal(err)
	}

	s.pruneAuditLog()

	if n := countRows(t, s, "audit_log"); n != auditKeepRows {
		t.Errorf("rows after count prune = %d, want %d", n, auditKeepRows)
	}
	// The three FRESH rows are older than the flood, so the cap evicted them first.
	var maxID, minID int
	_ = s.sqlite.QueryRow("SELECT MAX(id), MIN(id) FROM audit_log").Scan(&maxID, &minID)
	if maxID-minID != auditKeepRows-1 {
		t.Errorf("kept rows are not the newest contiguous block: min=%d max=%d", minID, maxID)
	}
}

// sweepSessions must delete every session the auth check can no longer accept.
func TestSweepSessions(t *testing.T) {
	s, _ := newTestServer(t)

	seed := []struct{ id, sql string }{
		{"expired", "INSERT INTO sessions (session_id, username, expires_at, created_at) VALUES ('expired', 'a', datetime('now', '-1 minute'), datetime('now'))"},
		{"overcap", "INSERT INTO sessions (session_id, username, expires_at, created_at) VALUES ('overcap', 'a', datetime('now', '+30 minutes'), datetime('now', '-13 hours'))"},
		{"legacy", "INSERT INTO sessions (session_id, username, expires_at) VALUES ('legacy', 'a', datetime('now', '+30 minutes'))"},
		{"valid", "INSERT INTO sessions (session_id, username, expires_at, created_at) VALUES ('valid', 'a', datetime('now', '+30 minutes'), datetime('now'))"},
	}
	for _, row := range seed {
		if _, err := s.sqlite.Exec(row.sql); err != nil {
			t.Fatalf("seed %s: %v", row.id, err)
		}
	}

	s.sweepSessions()

	rows, err := s.sqlite.Query("SELECT session_id FROM sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var left []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		left = append(left, id)
	}
	if len(left) != 1 || left[0] != "valid" {
		t.Errorf("sessions after sweep = %v, want [valid]", left)
	}
}

// maybeRunMaintenance must run at most once per interval.
func TestMaintenanceIntervalGate(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.SnapshotDir = t.TempDir()

	s.maybeRunMaintenance() // first call runs and stamps lastMaint

	if _, err := s.sqlite.Exec(
		"INSERT INTO sessions (session_id, username, expires_at, created_at) VALUES ('dead', 'a', datetime('now', '-1 minute'), datetime('now'))"); err != nil {
		t.Fatal(err)
	}
	s.maybeRunMaintenance() // gated: must not sweep yet
	if n := countRows(t, s, "sessions"); n != 1 {
		t.Errorf("gated call swept the session (rows=%d, want 1)", n)
	}

	s.lastMaint = s.lastMaint.Add(-2 * maintenanceInterval)
	s.maybeRunMaintenance() // interval elapsed: sweeps
	if n := countRows(t, s, "sessions"); n != 0 {
		t.Errorf("elapsed call did not sweep (rows=%d, want 0)", n)
	}
}

// A factory reset must remove the snapshot FILES with their rows - they carry
// the prior deployment's rendered configs.
func TestFactoryResetRemovesSnapshotFiles(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.SnapshotDir = t.TempDir()

	p := filepath.Join(s.cfg.SnapshotDir, "kea-dhcp4.1.conf")
	if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.sqlite.Exec("INSERT INTO config_snapshots (reason, path) VALUES ('test', ?)", p); err != nil {
		t.Fatal(err)
	}

	if err := s.factoryWipeDB(); err != nil {
		t.Fatalf("factoryWipeDB: %v", err)
	}
	if n := countRows(t, s, "config_snapshots"); n != 0 {
		t.Errorf("snapshot rows after reset = %d", n)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("snapshot file survived the factory reset")
	}
}
