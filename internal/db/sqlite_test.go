package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLastSeenRoundTrip checks the last_seen migration plus Upsert/Load: a batch
// writes, reloads to the same values, and a later upsert advances an existing row.
func TestLastSeenRoundTrip(t *testing.T) {
	sdb := openTestDB(t)

	if err := sdb.UpsertLastSeen(map[string]LastSeen{
		"aa:bb:cc:dd:ee:ff": {Identity: "aa:bb:cc:dd:ee:ff", Kind: "lease", LastSeen: 1000},
		"41:56:1f:65:74":    {Identity: "41:56:1f:65:74", Kind: "port", LastSeen: 2000},
	}); err != nil {
		t.Fatalf("UpsertLastSeen: %v", err)
	}

	got, err := sdb.LoadLastSeen()
	if err != nil {
		t.Fatalf("LoadLastSeen: %v", err)
	}
	if got["aa:bb:cc:dd:ee:ff"] != 1000 || got["41:56:1f:65:74"] != 2000 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// A later upsert advances the timestamp for an existing identity.
	if err := sdb.UpsertLastSeen(map[string]LastSeen{
		"aa:bb:cc:dd:ee:ff": {Identity: "aa:bb:cc:dd:ee:ff", Kind: "lease", LastSeen: 1500},
	}); err != nil {
		t.Fatalf("UpsertLastSeen advance: %v", err)
	}
	got, _ = sdb.LoadLastSeen()
	if got["aa:bb:cc:dd:ee:ff"] != 1500 {
		t.Errorf("advance not applied: got %d want 1500", got["aa:bb:cc:dd:ee:ff"])
	}

	// An empty batch is a no-op (and must not error).
	if err := sdb.UpsertLastSeen(nil); err != nil {
		t.Errorf("empty UpsertLastSeen errored: %v", err)
	}
}

// TestBusyTimeoutSet checks the connection pragma is applied on open.
func TestBusyTimeoutSet(t *testing.T) {
	sdb := openTestDB(t)

	var ms int
	if err := sdb.QueryRow("PRAGMA busy_timeout;").Scan(&ms); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if ms != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", ms)
	}
}

// TestDowngradeGuard verifies a database whose user_version is newer than this
// binary supports is refused (not self-healed, not silently run).
func TestDowngradeGuard(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	sdb, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	// Stamp a version far above any migration we ship, then reopen.
	if _, err := sdb.Exec("PRAGMA user_version = 9999;"); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
	sdb.Close()

	_, err = OpenSQLite(dbPath)
	if err == nil {
		t.Fatal("expected downgrade guard to reject a newer schema, got nil")
	}
	if !strings.Contains(err.Error(), "newer than this binary") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestCorruptSelfHeal verifies a non-SQLite (garbage) file at the db path is
// moved aside and a fresh, usable database is created, with a recovery marker.
func TestCorruptSelfHeal(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "appliance.db")
	if err := os.WriteFile(dbPath, []byte("this is not a sqlite database at all"), 0o600); err != nil {
		t.Fatalf("seed garbage file: %v", err)
	}

	sdb, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite should self-heal a corrupt file, got: %v", err)
	}
	defer sdb.Close()

	// The fresh database is usable and migrated (lifecycle state readable).
	if _, err := sdb.GetState(LifecycleStateKey); err != nil {
		t.Errorf("recreated db not usable: %v", err)
	}
	// A recovery marker was recorded for the UI banner.
	if v, _ := sdb.GetState("db_recovered_at"); v == "" {
		t.Error("expected db_recovered_at marker after self-heal")
	}
	// The corrupt file was moved aside.
	entries, _ := os.ReadDir(dir)
	var foundBackup bool
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			foundBackup = true
		}
	}
	if !foundBackup {
		t.Error("expected a .corrupt-<ts> backup file after self-heal")
	}
}

// TestForeignKeysCascadeAcrossPool proves PRAGMA foreign_keys is in force on the
// connection that runs deletes: deleting a profile must CASCADE-delete its scopes.
// This caught a real bug - the pragma was Exec'd on a pooled *sql.DB, so it only
// applied to one connection and CASCADE silently no-op'd on the others.
func TestForeignKeysCascadeAcrossPool(t *testing.T) {
	sdb := openTestDB(t)

	res, err := sdb.Exec("INSERT INTO profiles (name, active) VALUES ('p', 1)")
	if err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	if _, err := sdb.Exec(
		"INSERT INTO scopes (profile_id, iface_mode, cidr) VALUES (?, 'physical', '10.0.0.0/24')", pid); err != nil {
		t.Fatalf("insert scope: %v", err)
	}

	if _, err := sdb.Exec("DELETE FROM profiles WHERE id = ?", pid); err != nil {
		t.Fatalf("delete profile: %v", err)
	}
	var n int
	if err := sdb.QueryRow("SELECT COUNT(*) FROM scopes WHERE profile_id = ?", pid).Scan(&n); err != nil {
		t.Fatalf("count scopes: %v", err)
	}
	if n != 0 {
		t.Fatalf("scopes not CASCADE-deleted (n=%d); foreign_keys pragma not in force", n)
	}
}
