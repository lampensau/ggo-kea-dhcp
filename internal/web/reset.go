package web

import (
	"database/sql"
	"log"
	"net/http"
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
		if err := s.mariadb.DeleteAllReservations(); err != nil {
			log.Printf("[Reset] clearing Kea host reservations failed: %v", err)
		}
	}
	_, _ = s.sqlite.Exec("UPDATE profiles SET active = 0")
	// Clear the box-level WiFi uplink: in ONBOARDING wlan0 hosts the SoftAP, not a
	// client uplink, so these credentials can't apply and must not prefill the setup
	// wizard. Saved profiles keep their own uplink, so re-applying one restores it.
	_, _ = s.sqlite.Exec("DELETE FROM app_state WHERE key IN ('uplink_enabled','uplink_ssid','uplink_pass','uplink_dns')")
	return s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding)
}

func (s *Server) handleResetFactory(w http.ResponseWriter, r *http.Request) {
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
		if err := s.mariadb.DeleteAllReservations(); err != nil {
			log.Printf("[Reset] clearing Kea host reservations failed: %v", err)
		}
	}
	for _, q := range []string{
		"DELETE FROM scopes",
		"DELETE FROM profiles",
		"DELETE FROM port_labels",
		"DELETE FROM last_seen",
		"DELETE FROM audit_log",
		"DELETE FROM config_snapshots",
		"DELETE FROM sessions",
		"DELETE FROM users",
		"DELETE FROM app_state WHERE key IN ('onboarding_ip','softap_ssid','softap_pass','uplink_dns','global_dhcp_options','uplink_enabled','uplink_ssid','uplink_pass')",
	} {
		_, _ = s.sqlite.Exec(q)
	}
	// Drop the in-memory last-seen tracker too, so it doesn't repopulate the wiped
	// table from stale memory on the next sample.
	s.lastSeenMu.Lock()
	s.lastSeen = map[string]int64{}
	s.lastSeenWritten = map[string]int64{}
	s.lastSeenMu.Unlock()
	return s.sqlite.SetState(db.LifecycleStateKey, db.StateFactory)
}
