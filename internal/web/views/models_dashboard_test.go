package views

import "testing"

func TestAuditDotNormalizesSynonyms(t *testing.T) {
	cases := map[string]string{
		"SUCCESS": "ok", "OK": "ok",
		"ERROR": "err", "FAILED": "err", "FAILURE": "err",
		"WARNING": "warn",
		"INFO":    "", "MYSTERY": "",
	}
	for result, want := range cases {
		if got := auditDot(result); got != want {
			t.Errorf("auditDot(%q) = %q, want %q", result, got, want)
		}
	}
}
