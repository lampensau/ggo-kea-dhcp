package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/web/views"
)

// recentAuditRows returns the most recent audit-log entries (newest first), shared by
// the Diagnostics page (which absorbed the former Audit Log) and the dashboard feed's
// neighbours. Returns nil on a query error (logged) so callers can render an empty state.
func (s *Server) recentAuditRows(limit int) []views.AuditRow {
	rows, err := s.sqlite.Query("SELECT id, ts, actor, action, target, before_json, after_json, result FROM audit_log ORDER BY ts DESC LIMIT ?", limit)
	if err != nil {
		log.Printf("[Audit] query: %v", err)
		return nil
	}
	defer rows.Close()
	var logs []views.AuditRow
	for rows.Next() {
		var l views.AuditRow
		var before, after sql.NullString
		if rows.Scan(&l.ID, &l.Timestamp, &l.Actor, &l.Action, &l.Target, &before, &after, &l.Result) == nil {
			l.Timestamp = localAuditTime(l.Timestamp)
			l.Before, l.After = before.String, after.String
			logs = append(logs, l)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("[Audit] log iteration: %v", err)
	}
	return logs
}

// handleAudit redirects the retired /audit route to its new home on Diagnostics.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/diagnostics", http.StatusFound)
}

// handleReset redirects the retired /reset route to the Settings danger zone.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/settings", http.StatusFound)
}

func (s *Server) handleResetRoutine(w http.ResponseWriter, r *http.Request) {
	// Claim the mutation guard before touching state, so a reset can't race a
	// profile apply/switch (or another reconcile) writing the same kea.conf.
	if !s.beginReconcile() {
		s.handleError(w, r, reconcileBusyMsg, http.StatusConflict)
		return
	}
	log.Println("[Reset] Routine end-of-job reset to ONBOARDING...")
	if err := s.routineResetDB(); err != nil {
		s.endReconcile()
		s.handleError(w, r, "Failed to update appliance state", http.StatusInternalServerError)
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "RESET_ONBOARDING", "routine_reset", "", "", "SUCCESS")
	s.clearStagedUpdate()

	s.scheduleReconcileHeld("reset-routine", 1*time.Second, ModeApply, 0)

	s.respondInterstitial(w, ipOnly(s.onboardingCIDR()))
}

// routineResetDB performs the routine end-of-job reset's persistent mutations: keep
// the admin, profile library, and port labels, but deactivate the active profile,
// purge the Kea host store, and return to ONBOARDING. Port pins and reserved leases
// are per-job data-plane state - purge them from MariaDB (they survive a config reload
// otherwise) so a new job doesn't inherit the last event's reservations; port *labels*
// (the SQLite names) are kept so re-pinning a known port stays labelled. Split out from
// the handler so the DB effects are unit-testable without HTTP / the async reconcile.
func (s *Server) routineResetDB() error {
	if s.mariadb != nil {
		if err := s.mariadb.DeleteAllReservations(context.Background()); err != nil {
			log.Printf("[Reset] clearing Kea host reservations failed: %v", err)
		}
	}
	// One transaction, lifecycle write included: a crash between a committed
	// deactivate and the state flip would otherwise leave the box half-reset.
	tx, err := s.sqlite.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit
	_, e1 := tx.Exec("UPDATE profiles SET active = 0")
	// Clear the box-level WiFi uplink: in ONBOARDING wlan0 hosts the SoftAP, not a
	// client uplink, so these credentials can't apply and must not prefill the setup
	// wizard. Saved profiles keep their own uplink, so re-applying one restores it.
	_, e2 := tx.Exec("DELETE FROM app_state WHERE key IN ('uplink_enabled','uplink_ssid','uplink_pass','uplink_dns')")
	// Drop the self-update record too: ONBOARDING has no ACTIVE-gated update card,
	// so a leftover update_latest_* would light the footer badge with a dead
	// /settings#update anchor. LIKE-escape so only the update_* keys match.
	_, e3 := tx.Exec(`DELETE FROM app_state WHERE key LIKE 'update\_%' ESCAPE '\'`)
	// Clear any DHCP stand-down: it's per-job serving state. Inheriting it into the next
	// job's apply would render the holdoff config - ACTIVE but serving no leases.
	_, e5 := tx.Exec("DELETE FROM app_state WHERE key = ?", dhcpStandDownKey)
	_, e4 := tx.Exec(lifecycleUpsertSQL, db.LifecycleStateKey, db.StateOnboarding)
	if err := errors.Join(e1, e2, e3, e4, e5); err != nil {
		return err
	}
	return tx.Commit()
}

// lifecycleUpsertSQL mirrors db.SetState's upsert for use inside a transaction
// (the SQLite pool is pinned to one connection, so calling s.sqlite.SetState
// while a tx holds it would deadlock).
const lifecycleUpsertSQL = `
	INSERT INTO app_state (key, value) VALUES (?, ?)
	ON CONFLICT(key) DO UPDATE SET value = excluded.value`

func (s *Server) handleResetFactory(w http.ResponseWriter, r *http.Request) {
	// Re-auth before anything irreversible: a factory reset wipes the admin and
	// opens the pre-auth FACTORY window, so a click-through confirm is not enough.
	if ok, reason := s.reauthCurrentPassword(r); !ok {
		_ = s.sqlite.LogAudit(s.getActor(r), "RESET_FACTORY", "appliance", "", reason, "WARNING")
		s.handleError(w, r, reason, http.StatusBadRequest)
		return
	}
	if !s.beginReconcile() {
		s.handleError(w, r, reconcileBusyMsg, http.StatusConflict)
		return
	}
	log.Println("[Reset] Hard factory reset...")
	if err := s.factoryWipeDB(); err != nil {
		s.endReconcile()
		s.handleError(w, r, "Failed to reset appliance state", http.StatusInternalServerError)
		return
	}

	// The caller's session row is gone - clear its cookie too.
	clearSessionCookie(w, r)
	s.clearStagedUpdate()

	s.scheduleReconcileHeld("reset-factory", 1*time.Second, ModeApply, 0)

	s.respondInterstitial(w, ipOnly(s.onboardingCIDR()))
}

// factoryWipeDB performs the hard factory reset's persistent mutations: purge the Kea
// host store (port pins + MAC reservations live in MariaDB and would otherwise survive
// a "factory" reset entirely), then wipe everything in SQLite - including the admin and
// all sessions (D10) and the onboarding overrides so defaults return - and drop to
// FACTORY. Split out from the handler so the DB effects are unit-testable.
func (s *Server) factoryWipeDB() error {
	if s.mariadb != nil {
		if err := s.mariadb.DeleteAllReservations(context.Background()); err != nil {
			log.Printf("[Reset] clearing Kea host reservations failed: %v", err)
		}
	}
	// A silently-failed wipe is security-relevant: a "factory reset" that left the
	// admin/sessions rows while reporting success would hand the box to whoever held
	// the old credentials. One transaction, FACTORY state write included: committing
	// the users/sessions deletes without the state flip would strand a box that
	// demands login with zero admins (and /factory gated behind FACTORY) - a UI
	// lockout only manual DB surgery could undo. All-or-nothing instead.
	tx, err := s.sqlite.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit
	var wipeErr error
	for _, q := range []string{
		"DELETE FROM scopes",
		"DELETE FROM profiles",
		"DELETE FROM port_labels",
		"DELETE FROM last_seen",
		"DELETE FROM audit_log",
		"DELETE FROM config_snapshots",
		"DELETE FROM sessions",
		"DELETE FROM users",
		"DELETE FROM app_state WHERE key IN ('onboarding_ip','softap_ssid','softap_pass','uplink_dns','global_dhcp_options','uplink_enabled','uplink_ssid','uplink_pass','dhcp_standdown')",
		// The self-update record (badge/card state) must not survive a factory reset.
		`DELETE FROM app_state WHERE key LIKE 'update\_%' ESCAPE '\'`,
	} {
		if _, err := tx.Exec(q); err != nil {
			wipeErr = errors.Join(wipeErr, fmt.Errorf("%s: %w", q, err))
		}
	}
	if _, err := tx.Exec(lifecycleUpsertSQL, db.LifecycleStateKey, db.StateFactory); err != nil {
		wipeErr = errors.Join(wipeErr, fmt.Errorf("set FACTORY state: %w", err))
	}
	if wipeErr != nil {
		return wipeErr // rolled back by the deferred Rollback - nothing was wiped
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Drop the in-memory last-seen tracker too (after the commit, so a failed wipe
	// keeps memory and table consistent), so it doesn't repopulate the wiped table
	// from stale memory on the next sample.
	s.lastSeenMu.Lock()
	s.lastSeen = map[string]int64{}
	s.lastSeenWritten = map[string]int64{}
	s.lastSeenMu.Unlock()
	// The snapshot FILES belong to the rows the wipe just deleted; without this
	// they survive every factory reset and accumulate forever (the prior job's
	// rendered configs also linger for the next owner to read). Best-effort,
	// after the commit: a remove failure leaves orphans, never a failed reset.
	if entries, err := os.ReadDir(s.cfg.SnapshotDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				_ = os.Remove(filepath.Join(s.cfg.SnapshotDir, e.Name()))
			}
		}
	}
	return nil
}
