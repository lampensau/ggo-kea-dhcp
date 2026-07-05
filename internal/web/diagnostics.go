package web

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	v.Journal, v.JournalErr = s.journalTail()
	v.AptLog = s.aptLogTail()
	s.renderTempl(w, r, views.Diagnostics(v))
}

// logTailLines caps every Diagnostics log tail; the journalctl invocation asks
// for the same count, so this only re-trims the apt.log and defends the render.
const logTailLines = 200

// journalTail reads the service journal through the network layer's privileged
// seam (an exact-argument sudoers rule). Read-only; a failure degrades to an
// honest "not available" state on the page, never an error page - the operator
// opened Diagnostics precisely because something else is wrong.
func (s *Server) journalTail() ([]string, string) {
	out, err := s.net.ServiceLogTail()
	if err != nil {
		log.Printf("[diagnostics] journal tail: %v", err)
		return nil, "The service journal could not be read on this system."
	}
	lines := tailLines(out, logTailLines)
	if len(lines) == 0 {
		return nil, "The journal returned no entries."
	}
	return lines, ""
}

// aptLogTail returns the staged self-update apt.log when one exists (only after
// an update install has run; a reset clears it with the rest of the staging dir).
func (s *Server) aptLogTail() []string {
	b, err := os.ReadFile(filepath.Join(s.updateDir, updateAptLogFile))
	if err != nil {
		return nil
	}
	return tailLines(string(b), logTailLines)
}

// tailLines returns at most n trailing lines of text, without a trailing blank.
func tailLines(text string, n int) []string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
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
