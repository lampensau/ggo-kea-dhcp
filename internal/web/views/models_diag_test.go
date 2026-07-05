package views

import (
	"strings"
	"testing"
)

// TestFirmwareAuditPresentation: the collapsed summary shows only the compact census
// (never the roster, which would overflow the column), while the expanded explanation
// carries the roster - complementary, not mirrored.
func TestFirmwareAuditPresentation(t *testing.T) {
	r := AuditRow{
		Action: "Mixed Green-GO firmware",
		Target: "1 on 5.1.0, 1 on 5.2.2",
		After:  "BPX 19666 · 10.0.0.20 · 5.1.0.14479, BPX 19678 · 10.0.0.22 · 5.2.2.25270",
	}
	if got := auditSummary(r); got != r.Target {
		t.Errorf("collapsed summary should be the census only, got %q", got)
	}
	if e := auditExplain(r); !strings.Contains(e, "BPX 19666") || !strings.Contains(e, "5.2.2") {
		t.Errorf("expanded explanation should carry the roster, got %q", e)
	}
}
