package web

import (
	"log"
	"os"
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
	// auditKeepRows bounds the audit log by newest-N rowid. Deliberately NOT an
	// age window: the Pi has no RTC, so an NTP forward-jump would make pre-sync rows
	// instantly "old" and purge real history. rowid order is monotonic regardless of
	// the clock, so keeping the newest N is both the normal cap and the flood backstop.
	auditKeepRows = 5000
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
// deletes the rest, files included. One statement, DELETE ... RETURNING: a
// separate select-then-delete let a snapshot inserted between the two lose its
// row while its file survived as a permanent orphan. The cursor over the
// RETURNING rows is drained before any further statement (the pool is capped at
// one connection - buildBackup's closure pattern).
func (s *Server) pruneSnapshots() {
	paths, err := func() ([]string, error) {
		rows, err := s.sqlite.Query(
			"DELETE FROM config_snapshots WHERE id NOT IN (SELECT id FROM config_snapshots ORDER BY id DESC LIMIT ?) RETURNING path",
			snapshotKeepCount)
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
		log.Printf("[maintenance] prune snapshots: %v", err)
		return
	}
	if len(paths) == 0 {
		return
	}
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			log.Printf("[maintenance] remove old snapshot %s: %v", p, err)
		}
	}
	log.Printf("[maintenance] pruned %d old config snapshots", len(paths))
}

// pruneAuditLog keeps the newest auditKeepRows rows by rowid (clock-independent -
// see the const comment on why an age window is wrong on the RTC-less Pi).
func (s *Server) pruneAuditLog() {
	res, err := s.sqlite.Exec(
		`DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)`,
		auditKeepRows)
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
