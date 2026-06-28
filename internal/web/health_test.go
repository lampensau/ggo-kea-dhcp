package web

import (
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/preflight"
)

// TestBackendTrackerDebounce verifies DOWN is debounced by backendDownThreshold
// consecutive failures while UP (recovery) is reported on the first success.
func TestBackendTrackerDebounce(t *testing.T) {
	tr := backendTracker{healthy: true}

	// First failure: below threshold, no transition yet.
	if changed, _ := tr.observe(false, "boom"); changed {
		t.Fatal("first failure should not flip to DOWN (debounce)")
	}
	// Second consecutive failure: crosses threshold, DOWN transition.
	changed, healthy := tr.observe(false, "boom")
	if !changed || healthy {
		t.Fatalf("second failure should flip DOWN: changed=%v healthy=%v", changed, healthy)
	}
	// Still down, another failure: no new transition.
	if changed, _ := tr.observe(false, "boom"); changed {
		t.Fatal("staying down should not report a transition")
	}
	// Recovery: first success flips UP immediately.
	changed, healthy = tr.observe(true, "ok")
	if !changed || !healthy {
		t.Fatalf("first success should flip UP: changed=%v healthy=%v", changed, healthy)
	}
	// Staying up: no transition.
	if changed, _ := tr.observe(true, "ok"); changed {
		t.Fatal("staying up should not report a transition")
	}
}

// TestUplinkAuditDebounce verifies the uplink audit collapses repeated identical
// outcomes to one transition: the first observation always counts, repeats of the same
// state do not, and a flip does. This is what keeps a persistently failing (or re-saved
// working) uplink from spamming UPLINK_DOWN/UPLINK_UP on every reconcile.
func TestUplinkAuditDebounce(t *testing.T) {
	var u uplinkAudit

	// First down: counts (unknown -> down).
	if !u.observe(false) {
		t.Fatal("first observation should report a transition")
	}
	// Staying down: suppressed.
	if u.observe(false) {
		t.Fatal("repeated down should not report a transition")
	}
	// Recovery: down -> up counts.
	if !u.observe(true) {
		t.Fatal("down -> up should report a transition")
	}
	// Staying up (e.g. Settings re-saved unchanged): suppressed.
	if u.observe(true) {
		t.Fatal("repeated up should not report a transition")
	}
	// Going down again counts.
	if !u.observe(false) {
		t.Fatal("up -> down should report a transition")
	}
}

// TestBackendHealthAlertRows checks severity mapping: Kea down = err, MariaDB
// down = warn, both up = no rows.
func TestBackendHealthAlertRows(t *testing.T) {
	h := newBackendHealth()
	if rows := h.alertRows(); len(rows) != 0 {
		t.Fatalf("healthy: expected no rows, got %d", len(rows))
	}

	// Drive Kea down (two failures past threshold).
	h.observeKea(false, "x")
	h.observeKea(false, "x")
	rows := h.alertRows()
	if len(rows) != 1 || rows[0].Severity != "err" {
		t.Fatalf("kea down: expected one err row, got %+v", rows)
	}

	// Drive MariaDB down too.
	h.observeMariaDB(false, "y")
	h.observeMariaDB(false, "y")
	rows = h.alertRows()
	if len(rows) != 2 {
		t.Fatalf("both down: expected two rows, got %d", len(rows))
	}
	if rows[1].Severity != "warn" {
		t.Errorf("mariadb row should be warn, got %q", rows[1].Severity)
	}
}

// TestPreflightAlertRows checks the degraded-prerequisite summary that now rides the
// always-on backend-alert strip: all-OK -> no row; any Warn -> one warn row naming the
// affected checks and pointing to Diagnostics; any Fail -> one err row (Fail outranks
// Warn); the row collapses multiple bad checks into one banner.
func TestPreflightAlertRows(t *testing.T) {
	cases := []struct {
		name      string
		res       preflight.Result
		wantRows  int
		wantSev   string
		wantInDet string
	}{
		{"all ok", preflight.Result{{Name: "Kea binary", Status: preflight.OK}}, 0, "", ""},
		{"empty", preflight.Result{}, 0, "", ""},
		{"one warn", preflight.Result{
			{Name: "Kea binary", Status: preflight.OK},
			{Name: "CAP_NET_RAW (network monitor)", Status: preflight.Warn},
		}, 1, "warn", "CAP_NET_RAW"},
		{"fail outranks warn, one collapsed row", preflight.Result{
			{Name: "CAP_NET_RAW (network monitor)", Status: preflight.Warn},
			{Name: "Kea hooks", Status: preflight.Fail},
		}, 1, "err", "Kea hooks"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{}
			s.SetPreflight(c.res)
			rows := s.preflightAlertRows()
			if len(rows) != c.wantRows {
				t.Fatalf("rows=%d want %d (%+v)", len(rows), c.wantRows, rows)
			}
			if c.wantRows == 0 {
				return
			}
			if rows[0].Severity != c.wantSev {
				t.Errorf("severity=%q want %q", rows[0].Severity, c.wantSev)
			}
			if !strings.Contains(rows[0].Detail, c.wantInDet) {
				t.Errorf("detail %q missing %q", rows[0].Detail, c.wantInDet)
			}
			if !strings.Contains(rows[0].Detail, "Diagnostics") {
				t.Errorf("detail %q should point to Diagnostics", rows[0].Detail)
			}
		})
	}
}

// TestBackendHealthUplinkAlert proves a failed Wi-Fi uplink surfaces a warn banner row
// carrying the nmcli reason, and that it clears on reconnect.
func TestBackendHealthUplinkAlert(t *testing.T) {
	h := newBackendHealth()
	if rows := h.alertRows(); len(rows) != 0 {
		t.Fatalf("healthy: expected no rows, got %d", len(rows))
	}

	h.setUplinkDown(true, "Secrets were required, but not provided")
	rows := h.alertRows()
	if len(rows) != 1 || rows[0].Severity != "warn" || rows[0].Title != "Wi-Fi Uplink Offline" {
		t.Fatalf("uplink down: expected one warn 'Wi-Fi Uplink Offline' row, got %+v", rows)
	}
	if !strings.Contains(rows[0].Detail, "Secrets were required") {
		t.Errorf("uplink alert should carry the nmcli reason, got %q", rows[0].Detail)
	}

	h.setUplinkDown(false, "")
	if rows := h.alertRows(); len(rows) != 0 {
		t.Fatalf("after reconnect: expected no rows, got %+v", rows)
	}
}
