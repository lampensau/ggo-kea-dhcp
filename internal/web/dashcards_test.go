package web

import (
	"testing"

	"ggo-kea-dhcp/internal/web/views"
)

// TestLocalAuditTime verifies the audit timestamp conversion handles the format the
// pure-Go SQLite driver actually returns (RFC3339-UTC, "...T...Z"), not just the
// SQLite-native space form. The bug was that only the space form parsed, so real rows
// fell through and showed raw UTC (2h off in CEST). TZ-independent: it asserts both
// inputs (the same instant) render identically, that the RFC3339 input is actually
// converted (not echoed back), and that garbage passes through.
func TestLocalAuditTime(t *testing.T) {
	rfc := localAuditTime("2026-06-18T11:28:18Z")
	space := localAuditTime("2026-06-18 11:28:18")
	if rfc != space {
		t.Fatalf("same UTC instant rendered differently by format: RFC3339=%q space=%q", rfc, space)
	}
	if rfc == "2026-06-18T11:28:18Z" {
		t.Fatalf("RFC3339 input was not parsed/converted (fell through): %q", rfc)
	}
	if got := localAuditTime("not a timestamp"); got != "not a timestamp" {
		t.Fatalf("unparseable input should pass through verbatim, got %q", got)
	}
}

// TestDropOfflineRows: the dashboard card omits prober-confirmed-offline devices but
// keeps online and presence-unknown rows (prober unavailable must not empty the card).
func TestDropOfflineRows(t *testing.T) {
	rows := []views.LeaseRow{
		{IPAddress: "10.0.0.20", Presence: "online"},
		{IPAddress: "10.0.0.21", Presence: "offline"},
		{IPAddress: "10.0.0.22", Presence: ""},
	}
	got := dropOfflineRows(rows)
	if len(got) != 2 || got[0].IPAddress != "10.0.0.20" || got[1].IPAddress != "10.0.0.22" {
		t.Fatalf("expected online + unknown to survive, got %+v", got)
	}
}
