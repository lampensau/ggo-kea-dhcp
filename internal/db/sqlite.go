package db

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type SQLiteDB struct {
	*sql.DB
}

// LifecycleStateKey is the app_state key holding the current lifecycle state.
const LifecycleStateKey = "lifecycle_state"

// Lifecycle states, persisted in app_state under LifecycleStateKey. Defined
// here (the owner of app_state) so the state machine never compares against
// bare string literals scattered across packages.
const (
	StateFactory    = "FACTORY"
	StateOnboarding = "ONBOARDING"
	// StateConfiguring is a persisted transient state held for the duration of a
	// profile apply. Persisting it (rather than relying on an in-memory flag)
	// makes a crash mid-apply recoverable: a box found in CONFIGURING at boot had
	// its apply interrupted and is reverted to ONBOARDING by the reconciler.
	StateConfiguring = "CONFIGURING"
	StateActive      = "ACTIVE"
)

// errCorruptDB marks a database that failed to open/migrate because the file is
// not a valid, intact SQLite database (malformed image or not-a-database). It is
// the trigger for the self-heal path in OpenSQLite; ordinary errors (permissions,
// a newer-than-supported schema) are not corruption and are never self-healed.
var errCorruptDB = errors.New("sqlite database is corrupt")

// SQLite primary result codes we treat as corruption (see modernc.org/sqlite/lib).
const (
	sqliteCorrupt = 11 // SQLITE_CORRUPT - the database disk image is malformed
	sqliteNotADB  = 26 // SQLITE_NOTADB  - file opened that is not a database file
)

// OpenSQLite opens the control-plane database and runs migrations. If the file is
// corrupt it self-heals: the bad file is moved aside (appliance.db.corrupt-<ts>)
// and a fresh database is created, so a headless box boots into FACTORY rather
// than bricking. Prior control-plane data is lost on self-heal - the operator
// restores it from a backup (see the full-stack backup/restore). The recovery is
// recorded in app_state (db_recovered_at / db_recovered_from) for a one-time UI
// banner.
func OpenSQLite(dbPath string) (*SQLiteDB, error) {
	sdb, err := openAndMigrate(dbPath)
	if err == nil {
		return sdb, nil
	}
	if !errors.Is(err, errCorruptDB) {
		// Not corruption (e.g. permissions, or a schema newer than this binary):
		// surface as-is; the caller treats it as fatal.
		return nil, err
	}

	backup := fmt.Sprintf("%s.corrupt-%d", dbPath, time.Now().Unix())
	log.Printf("WARNING: control-plane database %q failed its integrity check (%v); moving it aside to %q and recreating a fresh database. Prior data (users, profiles, scopes) is lost - restore from a backup to recover.", dbPath, err, backup)
	if mvErr := moveDBAside(dbPath, backup); mvErr != nil {
		return nil, fmt.Errorf("database corrupt and could not be moved aside: %w", mvErr)
	}

	sdb, err = openAndMigrate(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to recreate database after corruption: %w", err)
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	if e := sdb.SetStates(map[string]string{"db_recovered_at": now, "db_recovered_from": backup}); e != nil {
		log.Printf("Warning: failed to record database recovery marker: %v", e)
	}
	return sdb, nil
}

// openAndMigrate opens the database, applies the connection pragmas, verifies
// integrity, and runs migrations. Corruption encountered at any of these steps is
// classified as errCorruptDB so OpenSQLite can self-heal.
func openAndMigrate(dbPath string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Pin the pool to ONE connection. foreign_keys and busy_timeout are
	// per-connection pragmas: set on a pooled *sql.DB they would apply only to
	// whichever connection happened to run the Exec, silently leaving CASCADE
	// (scopes ON DELETE CASCADE) OFF on every other connection. One connection
	// makes them stick - and serialized access is the right model for this
	// single-operator embedded DB (it also removes SQLITE_BUSY entirely).
	//
	// FOOTGUN: with a single connection, an open *sql.Rows cursor holds the only
	// connection until it is drained or Closed. Any query issued on this same handle
	// WHILE a cursor is still open therefore waits for a connection that never frees
	// - a hard, whole-DB DEADLOCK, not the mere connection leak it would be on a
	// multi-conn pool. Always finish/Close a Rows before the next query on this
	// handle (iterate it fully, or collect rows into a slice and Close, THEN query).
	db.SetMaxOpenConns(1)

	// WAL + foreign keys for integrity; busy_timeout as a backstop.
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"); err != nil {
		db.Close()
		return nil, classifyDBErr("failed to configure sqlite parameters", err)
	}

	sdb := &SQLiteDB{db}
	if err := sdb.integrityCheck(); err != nil {
		db.Close()
		return nil, err
	}
	if err := sdb.runMigrations(); err != nil {
		db.Close()
		return nil, classifyDBErr("database migrations failed", err)
	}

	return sdb, nil
}

// integrityCheck runs PRAGMA integrity_check and returns errCorruptDB unless the
// single expected "ok" row comes back.
func (db *SQLiteDB) integrityCheck() error {
	rows, err := db.Query("PRAGMA integrity_check;")
	if err != nil {
		return classifyDBErr("integrity check failed", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return classifyDBErr("integrity check scan failed", err)
		}
		results = append(results, s)
	}
	if err := rows.Err(); err != nil {
		return classifyDBErr("integrity check read failed", err)
	}
	if len(results) != 1 || !strings.EqualFold(results[0], "ok") {
		return fmt.Errorf("%w: %s", errCorruptDB, strings.Join(results, "; "))
	}
	return nil
}

// classifyDBErr wraps err, tagging it as errCorruptDB when the underlying SQLite
// result code indicates a malformed/not-a-database file.
func classifyDBErr(context string, err error) error {
	if isCorruptionErr(err) {
		return fmt.Errorf("%s: %w (%v)", context, errCorruptDB, err)
	}
	return fmt.Errorf("%s: %w", context, err)
}

// isCorruptionErr reports whether err is a SQLite corruption / not-a-database error.
func isCorruptionErr(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqliteCorrupt, sqliteNotADB:
			return true
		}
	}
	return false
}

// moveDBAside renames the database file (and its -wal/-shm sidecars, best effort)
// out of the way so a fresh database can be created at the original path.
func moveDBAside(dbPath, backup string) error {
	if err := os.Rename(dbPath, backup); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Rename(dbPath+suffix, backup+suffix)
	}
	return nil
}

func (db *SQLiteDB) runMigrations() error {
	// 1. Get current user_version
	var currentVersion int
	err := db.QueryRow("PRAGMA user_version;").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to read user_version: %w", err)
	}

	// 2. Read embedded migrations
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	type migration struct {
		version int
		name    string
		sql     string
	}

	var migrations []migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) < 2 {
			continue
		}

		ver, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Printf("Warning: skipping invalid migration filename format: %s", entry.Name())
			continue
		}

		sqlBytes, err := migrationFS.ReadFile(filepath.Join("migrations", entry.Name()))
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", entry.Name(), err)
		}

		migrations = append(migrations, migration{
			version: ver,
			name:    entry.Name(),
			sql:     string(sqlBytes),
		})
	}

	// Sort migrations by version ascending
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	// Downgrade guard: a database written by a newer binary (user_version higher
	// than any migration we ship) must not run against our older schema - that can
	// silently corrupt data. Refuse to boot with a clear message. This is the one
	// database condition treated as fatal rather than self-healing.
	if len(migrations) > 0 {
		maxVer := migrations[len(migrations)-1].version
		if currentVersion > maxVer {
			return fmt.Errorf("database schema version %d is newer than this binary supports (max %d); upgrade the ggo-kea-dhcp binary", currentVersion, maxVer)
		}
	}

	// 3. Execute pending migrations in a transaction
	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}

		log.Printf("Running database migration %s (version %d)...", m.name, m.version)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to start migration transaction: %w", err)
		}

		// Split migration SQL into individual statements
		// This is a simple parser that splits by semicolon.
		// For migrations containing triggers/stored procedures with semicolons, we'd need a more advanced parser,
		// but simple semicolon splitting is perfect for our control plane schema.
		for query := range strings.SplitSeq(m.sql, ";") {
			trimmed := strings.TrimSpace(query)
			if trimmed == "" {
				continue
			}
			if _, err := tx.Exec(trimmed); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("failed executing migration statement in %s:\n%s\nError: %w", m.name, trimmed, err)
			}
		}

		// Update user_version
		pragmaCmd := fmt.Sprintf("PRAGMA user_version = %d;", m.version)
		if _, err := tx.Exec(pragmaCmd); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed updating user_version to %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration transaction: %w", err)
		}
		log.Printf("Migration %d successfully completed.", m.version)
	}

	return nil
}

// LogAudit logs an operation to the audit log in SQLite.
func (db *SQLiteDB) LogAudit(actor, action, target, beforeJSON, afterJSON, result string) error {
	_, err := db.Exec(`
		INSERT INTO audit_log (actor, action, target, before_json, after_json, result)
		VALUES (?, ?, ?, ?, ?, ?)`,
		actor, action, target, beforeJSON, afterJSON, result)
	return err
}

// SetState updates or inserts a key-value pair in app_state.
func (db *SQLiteDB) SetState(key, value string) error {
	_, err := db.Exec(`
		INSERT INTO app_state (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

// SetStates upserts multiple app_state key/value pairs atomically: either all
// land or none do, so a mid-write failure can't leave settings half-applied.
func (db *SQLiteDB) SetStates(kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO app_state (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for k, v := range kv {
		if _, err := stmt.Exec(k, v); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// LastSeen is one row of the last_seen table: when an identity (a normalized MAC for
// a lease, a flex-id key for a switch port) was last observed active.
type LastSeen struct {
	Identity string
	Kind     string
	LastSeen int64
}

// LoadLastSeen reads the whole last_seen table into an identity -> epoch map, used to
// prime the in-memory tracker at startup.
func (db *SQLiteDB) LoadLastSeen() (map[string]int64, error) {
	rows, err := db.Query("SELECT identity, last_seen FROM last_seen")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var id string
		var ts int64
		if err := rows.Scan(&id, &ts); err != nil {
			return nil, err
		}
		out[id] = ts
	}
	return out, rows.Err()
}

// UpsertLastSeen writes a batch of last-seen rows in one transaction. The caller only
// passes rows whose timestamp has advanced (the sampler gates on that to spare the
// Pi's SD card), so this is a plain upsert to the latest value.
func (db *SQLiteDB) UpsertLastSeen(rows map[string]LastSeen) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO last_seen (identity, kind, last_seen)
		VALUES (?, ?, ?)
		ON CONFLICT(identity) DO UPDATE SET last_seen = excluded.last_seen, kind = excluded.kind`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Identity, r.Kind, r.LastSeen); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// GetState reads a value from app_state by key. Returns empty string if not found.
func (db *SQLiteDB) GetState(key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM app_state WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}
