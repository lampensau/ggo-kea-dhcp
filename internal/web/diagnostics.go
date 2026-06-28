package web

import (
	"net/http"
	"strconv"
	"time"

	"ggo-kea-dhcp/internal/preflight"
	"ggo-kea-dhcp/internal/web/views"
)

// handleDiagnostics renders the Diagnostics page: it re-runs the preflight probes
// (so a fixed prerequisite clears on reload), shows any database-recovery notice,
// and lists the recent SYSTEM audit events (preflight results, backend up/down).
func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	res := preflight.Run(s.cfg)
	s.SetPreflight(res)
	// Re-probing here may change the degraded-prerequisite summary in the always-on
	// #backend-alert strip; push it so other open pages reflect the new state without
	// waiting for a navigation. (First paint already carries it via backendAlertRows.)
	s.publishBackendAlert()

	checks := make([]views.DiagRow, 0, len(res))
	degraded := false
	for _, c := range res {
		if c.Status != preflight.OK {
			degraded = true
		}
		checks = append(checks, views.DiagRow{Status: string(c.Status), Name: c.Name, Detail: c.Detail})
	}

	v := views.DiagnosticsView{
		Page:     s.pageData(w, r, "Diagnostics"),
		Checks:   checks,
		Degraded: degraded,
		Recovery: s.dbRecoveryNotice(),
		Logs:     s.recentAuditRows(50),
	}
	s.renderTempl(w, r, views.Diagnostics(v))
}

// dbRecoveryNotice returns a notice when the control-plane database was reset after
// corruption at boot (markers written by db.OpenSQLite), or nil otherwise.
func (s *Server) dbRecoveryNotice() *views.DiagRecovery {
	at, _ := s.sqlite.GetState("db_recovered_at")
	if at == "" {
		return nil
	}
	when := at
	if epoch, err := strconv.ParseInt(at, 10, 64); err == nil {
		when = time.Unix(epoch, 0).Format("2006-01-02 15:04:05")
	}
	from, _ := s.sqlite.GetState("db_recovered_from")
	return &views.DiagRecovery{When: when, From: from}
}
