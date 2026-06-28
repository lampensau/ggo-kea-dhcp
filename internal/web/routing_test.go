package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestIsUnsafeMethod tables the CSRF-relevant method classifier: the four
// mutating verbs are unsafe; everything else (incl. lowercase, which net/http
// canonicalizes upstream, and unknown verbs) is safe.
func TestIsUnsafeMethod(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{"POST", true},
		{"PUT", true},
		{"PATCH", true},
		{"DELETE", true},
		{"GET", false},
		{"HEAD", false},
		{"OPTIONS", false},
		{"TRACE", false},
		{"CONNECT", false},
		{"", false},
		{"post", false}, // case-sensitive: only the canonical net/http constants match
	}
	for _, c := range cases {
		if got := isUnsafeMethod(c.method); got != c.want {
			t.Errorf("isUnsafeMethod(%q)=%v want %v", c.method, got, c.want)
		}
	}
}

// TestStateRedirectFor_Extra adds coverage beyond server_test.go's table:
// the ONBOARDING whitelist's lesser-known entries, an unknown state, and the
// CONFIGURING pass-through for non-setup paths.
func TestStateRedirectFor_Extra(t *testing.T) {
	cases := []struct {
		state, path, want string
	}{
		// ONBOARDING whitelist members all pass.
		{db.StateOnboarding, "/setup/pools/edit", ""},
		{db.StateOnboarding, "/settings", ""},
		{db.StateOnboarding, "/settings/backup", ""},
		{db.StateOnboarding, "/settings/restore", ""},
		{db.StateOnboarding, "/wifi/scan", ""},
		// ONBOARDING non-whitelist paths bounce to /setup.
		{db.StateOnboarding, "/leases", "/setup"},
		{db.StateOnboarding, "/", "/setup"},
		{db.StateOnboarding, "/audit", "/setup"},
		// CONFIGURING only blocks the wizard; everything else proceeds.
		{db.StateConfiguring, "/setup/apply", "/dashboard"},
		{db.StateConfiguring, "/leases", ""},
		{db.StateConfiguring, "/sse/live", ""},
		// ACTIVE allows the wizard and all dashboard pages.
		{db.StateActive, "/settings", ""},
		{db.StateActive, "/leases", ""},
		// An unexpected/empty state is permissive (no redirect from this pure fn).
		{"WEIRD", "/dashboard", ""},
		{"", "/dashboard", ""},
	}
	for _, c := range cases {
		if got := stateRedirectFor(c.state, c.path); got != c.want {
			t.Errorf("stateRedirectFor(%q,%q)=%q want %q", c.state, c.path, got, c.want)
		}
	}
}

// TestRegionOnPage covers the live-hub region routing matrix: shell regions
// reach every page, an unknown referer falls back to "send everything", and
// page-specific regions are gated to their page.
func TestRegionOnPage(t *testing.T) {
	cases := []struct {
		region, page string
		want         bool
	}{
		// Shell regions: every page.
		{"state-badge", "/dashboard", true},
		{"state-badge", "/leases", true},
		{"sys-health", "/audit", true},
		{"sys-health", "/setup", true},
		// Unknown / root referer: don't drop anything.
		{"leases-body", "", true},
		{"pinnings", "/", true},
		{"anything", "", true},
		// Dashboard regions.
		{"dash-tiles", "/dashboard", true},
		{"dash-lldp", "/dashboard", true}, // live LLDP chip must reach the dashboard
		{"pool-table", "/dashboard", true},
		{"net-health", "/dashboard", true},
		{"pinnings", "/dashboard", true},
		{"leases-body", "/dashboard", false}, // leases body is not on the dashboard
		// Leases page.
		{"leases-body", "/leases", true},
		{"dash-tiles", "/leases", false},
		// Pinning page.
		{"pinned-body", "/pinning", true},
		{"learnable-head", "/pinning", true},
		{"leases-body", "/pinning", false},
		// Setup wizard: only the link-status badge.
		{"link-status", "/setup", true},
		{"dash-tiles", "/setup", false},
		// A page with no live regions of its own gets nothing but shell regions.
		{"dash-tiles", "/audit", false},
		{"pool-table", "/settings", false},
	}
	for _, c := range cases {
		if got := regionOnPage(c.region, c.page); got != c.want {
			t.Errorf("regionOnPage(%q,%q)=%v want %v", c.region, c.page, got, c.want)
		}
	}
}

// TestHandleAPIState_Default asserts a fresh (FACTORY) box reports FACTORY
// as plain text with a no-store cache header.
func TestHandleAPIState_Default(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/state", nil)
	w := httptest.NewRecorder()
	s.handleAPIState(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d want 200", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != db.StateFactory {
		t.Errorf("body = %q want %q", got, db.StateFactory)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q want no-store", cc)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q want text/plain", ct)
	}
}

// TestHandleAPIState_Active asserts the handler echoes whatever lifecycle
// state is persisted (the CONFIGURING page polls this to detect the flip to ACTIVE).
func TestHandleAPIState_Active(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}
	req := httptest.NewRequest("GET", "/api/state", nil)
	w := httptest.NewRecorder()
	s.handleAPIState(w, req)

	if got := strings.TrimSpace(w.Body.String()); got != db.StateActive {
		t.Errorf("body = %q want %q", got, db.StateActive)
	}
}
