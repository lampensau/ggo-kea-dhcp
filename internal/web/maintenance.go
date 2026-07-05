package web

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Storage maintenance: the appliance lives on an SD card, so every store that
// grows per event (config snapshots, audit rows, sessions) is bounded here.
// Rides the always-on metrics sampler tick (no extra timer) but runs its
// DELETEs only once per maintenanceInterval - and a DELETE that matches
// nothing touches no pages, so the steady-state cost is a few index probes.
const (
	maintenanceInterval = time.Hour
	// snapshotKeepCount bounds config_snapshots (one row + file per apply/switch).
	// The rollback path holds its snapshot path in the in-flight plan, never this
	// index, so keeping a recent window purely for the operator is safe.
	snapshotKeepCount = 20
	// auditKeepRows / auditKeepDays bound the audit log: age is the normal cap,
	// the row cap is the backstop against an event flood (e.g. a flapping
	// detector) filling the SD card within the age window.
	auditKeepRows = 5000
	auditKeepDays = 90
)

// maybeRunMaintenance runs the pruning pass at most once per maintenanceInterval.
// Called only from the metrics sampler goroutine, so lastMaint needs no lock.
func (s *Server) maybeRunMaintenance() {
	if time.Since(s.lastMaint) < maintenanceInterval {
		return
	}
	s.lastMaint = time.Now()
	s.pruneSnapshots()
	s.pruneAuditLog()
	s.sweepSessions()
}

// pruneSnapshots keeps the newest snapshotKeepCount config_snapshots rows and
// deletes the rest, files included.
func (s *Server) pruneSnapshots() {
	// Collect the victims' paths BEFORE any further statement: the SQLite pool is
	// capped at one connection, so issuing a query while a *sql.Rows cursor is
	// open deadlocks the control plane (buildBackup's closure pattern).
	paths, err := func() ([]string, error) {
		rows, err := s.sqlite.Query(
			"SELECT path FROM config_snapshots ORDER BY id DESC LIMIT -1 OFFSET ?", snapshotKeepCount)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var p string
			if rows.Scan(&p) == nil {
				out = append(out, p)
			}
		}
		return out, rows.Err()
	}()
	if err != nil {
		log.Printf("[maintenance] list old snapshots: %v", err)
		return
	}
	if len(paths) == 0 {
		return
	}

	if _, err := s.sqlite.Exec(
		"DELETE FROM config_snapshots WHERE id NOT IN (SELECT id FROM config_snapshots ORDER BY id DESC LIMIT ?)",
		snapshotKeepCount); err != nil {
		log.Printf("[maintenance] prune snapshot rows: %v", err)
		return // keep the files while their rows still exist
	}
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			log.Printf("[maintenance] remove old snapshot %s: %v", p, err)
		}
	}
	log.Printf("[maintenance] pruned %d old config snapshots", len(paths))
}

// pruneAuditLog drops audit rows past the age window, with a row-count backstop.
func (s *Server) pruneAuditLog() {
	res, err := s.sqlite.Exec(
		`DELETE FROM audit_log WHERE ts < datetime('now', ?)
		   OR id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)`,
		"-"+strconv.Itoa(auditKeepDays)+" days", auditKeepRows)
	if err != nil {
		log.Printf("[maintenance] prune audit log: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[maintenance] pruned %d audit rows", n)
	}
}

// sweepSessions deletes sessions that can never validate again: past their
// sliding expiry, past the 12-hour absolute cap, or legacy rows without a
// created_at (which the auth check already rejects).
func (s *Server) sweepSessions() {
	if _, err := s.sqlite.Exec(
		`DELETE FROM sessions WHERE expires_at <= datetime('now')
		   OR created_at <= datetime('now', '-12 hours')
		   OR created_at IS NULL`); err != nil {
		log.Printf("[maintenance] sweep sessions: %v", err)
	}
}
