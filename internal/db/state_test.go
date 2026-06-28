package db

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// highestMigration reads the embedded migrations and returns the version the newest
// one stamps, so the user_version assertions don't hardcode a number that every new
// migration silently breaks.
func highestMigration(t *testing.T) int {
	t.Helper()
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	top := 0
	for _, e := range entries {
		n, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err == nil && n > top {
			top = n
		}
	}
	if top == 0 {
		t.Fatal("no numbered migrations found")
	}
	return top
}

// openTestDB is the shared temp-DB helper for the harness tests (mirrors the
// pattern in sqlite_test.go).
func openTestDB(t *testing.T) *SQLiteDB {
	t.Helper()
	sdb, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { sdb.Close() })
	return sdb
}

// TestStateRoundTrip covers GetState/SetState insert, overwrite-on-conflict, and
// the missing-key contract (empty string, no error).
func TestStateRoundTrip(t *testing.T) {
	sdb := openTestDB(t)

	if v, err := sdb.GetState("nope"); err != nil || v != "" {
		t.Errorf("GetState(missing) = (%q,%v), want (\"\",nil)", v, err)
	}

	if err := sdb.SetState("k1", "v1"); err != nil {
		t.Fatalf("SetState insert: %v", err)
	}
	if v, _ := sdb.GetState("k1"); v != "v1" {
		t.Errorf("GetState(k1) = %q, want v1", v)
	}

	// ON CONFLICT updates in place.
	if err := sdb.SetState("k1", "v2"); err != nil {
		t.Fatalf("SetState overwrite: %v", err)
	}
	if v, _ := sdb.GetState("k1"); v != "v2" {
		t.Errorf("GetState(k1) after overwrite = %q, want v2", v)
	}
}

// TestSetStatesAtomicBatch verifies a multi-key batch lands and an empty batch is
// a no-op.
func TestSetStatesAtomicBatch(t *testing.T) {
	sdb := openTestDB(t)

	if err := sdb.SetStates(nil); err != nil {
		t.Errorf("empty SetStates errored: %v", err)
	}

	want := map[string]string{"a": "1", "b": "2", "c": "3"}
	if err := sdb.SetStates(want); err != nil {
		t.Fatalf("SetStates: %v", err)
	}
	for k, v := range want {
		if got, _ := sdb.GetState(k); got != v {
			t.Errorf("GetState(%q) = %q, want %q", k, got, v)
		}
	}

	// A second batch updates existing keys (excluded.value path).
	if err := sdb.SetStates(map[string]string{"a": "10"}); err != nil {
		t.Fatalf("SetStates update: %v", err)
	}
	if got, _ := sdb.GetState("a"); got != "10" {
		t.Errorf("GetState(a) after update = %q, want 10", got)
	}
}

// TestLoadLastSeenPopulatedKinds confirms LoadLastSeen returns the full table
// (both lease and port kinds) keyed by identity with the stored epoch.
func TestLoadLastSeenPopulatedKinds(t *testing.T) {
	sdb := openTestDB(t)

	in := map[string]LastSeen{
		"aa:bb:cc:dd:ee:01": {Identity: "aa:bb:cc:dd:ee:01", Kind: "lease", LastSeen: 111},
		"aa:bb:cc:dd:ee:02": {Identity: "aa:bb:cc:dd:ee:02", Kind: "lease", LastSeen: 222},
		"port-key-3":        {Identity: "port-key-3", Kind: "port", LastSeen: 333},
	}
	if err := sdb.UpsertLastSeen(in); err != nil {
		t.Fatalf("UpsertLastSeen: %v", err)
	}
	got, err := sdb.LoadLastSeen()
	if err != nil {
		t.Fatalf("LoadLastSeen: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("LoadLastSeen size = %d, want 3: %+v", len(got), got)
	}
	for id, ls := range in {
		if got[id] != ls.LastSeen {
			t.Errorf("LoadLastSeen[%q] = %d, want %d", id, got[id], ls.LastSeen)
		}
	}
}

// TestMigrationsApplyUserVersion proves openAndMigrate ran every embedded
// migration and stamped user_version to the highest one.
func TestMigrationsApplyUserVersion(t *testing.T) {
	sdb := openTestDB(t)

	var ver int
	if err := sdb.QueryRow("PRAGMA user_version;").Scan(&ver); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if want := highestMigration(t); ver != want {
		t.Errorf("user_version = %d, want %d (highest embedded migration)", ver, want)
	}

	// The schema is usable: core tables created by migrations exist and are queryable.
	for _, table := range []string{"app_state", "profiles", "scopes", "last_seen", "audit_log"} {
		if _, err := sdb.Exec("SELECT 1 FROM " + table + " LIMIT 1"); err != nil {
			t.Errorf("expected table %q to exist after migrations: %v", table, err)
		}
	}
}

// TestMigrationsIdempotentOnReopen confirms reopening an already-migrated database
// is a no-op (user_version unchanged, no error) - openAndMigrate skips applied
// versions.
func TestMigrationsIdempotentOnReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	sdb, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("first OpenSQLite: %v", err)
	}
	if err := sdb.SetState("survivor", "yes"); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	sdb.Close()

	sdb2, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("reopen OpenSQLite: %v", err)
	}
	defer sdb2.Close()

	var ver int
	if err := sdb2.QueryRow("PRAGMA user_version;").Scan(&ver); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if want := highestMigration(t); ver != want {
		t.Errorf("user_version after reopen = %d, want %d", ver, want)
	}
	if v, _ := sdb2.GetState("survivor"); v != "yes" {
		t.Errorf("data did not survive reopen: GetState(survivor) = %q", v)
	}
}
