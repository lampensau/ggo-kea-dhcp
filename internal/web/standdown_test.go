package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/web/views"
)

// TestBuildRogueRows covers the three banner states: a live rogue promotes to a loud
// error row with the stand-down control; a stood-down box shows the operator-hold warn
// row with the resume control (winning over any live detection); nothing yields no row.
func TestBuildRogueRows(t *testing.T) {
	rogue := rogueSighting{Server: "192.0.2.7", MAC: "aa:bb:cc:dd:ee:ff", Iface: "eth0", Sustained: true}

	rows := buildRogueRows(false, []rogueSighting{rogue}, "about 30 minutes")
	if len(rows) != 1 || rows[0].Severity != "err" || rows[0].Action != "standdown" {
		t.Fatalf("live rogue rows = %+v, want one err/standdown row", rows)
	}
	if !strings.Contains(rows[0].Detail, "192.0.2.7") || !strings.Contains(rows[0].Detail, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("rogue detail must name the server IP and MAC: %q", rows[0].Detail)
	}
	if rows[0].LeaseHint != "about 30 minutes" {
		t.Errorf("standdown row should carry the lease hint for the dialog, got %q", rows[0].LeaseHint)
	}

	// A present-but-not-sustained rogue (a single, forgeable OFFER) must NOT raise the
	// loud one-click stand-down banner - only the quieter Network Health row.
	transient := rogueSighting{Server: "192.0.2.7", MAC: "aa:bb:cc:dd:ee:ff", Iface: "eth0"} // Sustained: false
	if rows := buildRogueRows(false, []rogueSighting{transient}, ""); rows != nil {
		t.Errorf("a transient (unsustained) rogue must not raise the stand-down banner, got %+v", rows)
	}

	// Stood down wins even while the rogue is still visible.
	held := buildRogueRows(true, []rogueSighting{rogue}, "about 30 minutes")
	if len(held) != 1 || held[0].Severity != "warn" || held[0].Action != "resume" {
		t.Fatalf("stood-down rows = %+v, want one warn/resume row", held)
	}
	if !strings.Contains(held[0].Detail, "not stopped") || !strings.Contains(held[0].Detail, "30 minutes") {
		t.Errorf("stood-down banner must state the rogue is not stopped and reference the lease lifetime: %q", held[0].Detail)
	}

	if rows := buildRogueRows(false, nil, ""); rows != nil {
		t.Errorf("no rogue and not stood down should yield no row, got %+v", rows)
	}
}

// TestBackendAlertRendersRogueControls proves the strip renders the operator controls
// as POSTs to the stand-down / resume endpoints, and that an attacker-influenced MAC in
// the detail is HTML-escaped (never emitted as live markup).
func TestBackendAlertRendersRogueControls(t *testing.T) {
	evil := rogueSighting{Server: "192.0.2.7", MAC: `x"><script>alert(1)</script>`, Iface: "eth0", Sustained: true}
	strip := renderFragment(views.BackendAlert(buildRogueRows(false, []rogueSighting{evil}, "about 30 minutes")))
	if !strings.Contains(strip, `action="/rogue/standdown"`) || !strings.Contains(strip, "Stand Down DHCP") {
		t.Errorf("rogue strip missing the stand-down control:\n%s", strip)
	}
	if strings.Contains(strip, "<script>alert(1)</script>") {
		t.Errorf("attacker MAC was not escaped in the rendered strip:\n%s", strip)
	}

	held := renderFragment(views.BackendAlert(buildRogueRows(true, nil, "about 30 minutes")))
	if !strings.Contains(held, `action="/rogue/resume"`) || !strings.Contains(held, "Resume DHCP") {
		t.Errorf("stood-down strip missing the resume control:\n%s", held)
	}
}

// TestRogueBannerCountsMultiplePerInterface proves the banner reports the honest total
// when several foreign servers answer on ONE interface: the snapshot names only the first
// (its Fields carry a single IP/MAC) but a Count of 2, so the headline and detail must
// still count both, not collapse to "1".
func TestRogueBannerCountsMultiplePerInterface(t *testing.T) {
	rogues := []rogueSighting{{Server: "10.0.0.254", MAC: "aa:aa:aa:aa:aa:aa", Iface: "eth0", Count: 2}}
	if got := rogueAlertTitle(rogues); got != "2 rogue DHCP servers detected" {
		t.Errorf("title = %q, want the honest 2-server count", got)
	}
	if detail := rogueAlertDetail(rogues); !strings.Contains(detail, "10.0.0.254") || !strings.Contains(detail, "and 1 more") {
		t.Errorf("detail should name the first server and count the other: %q", detail)
	}
	if audit := rogueAuditDetail(rogues); !strings.Contains(audit, "2 servers total") {
		t.Errorf("audit detail should note the total when it exceeds named servers: %q", audit)
	}

	// A single server (Count 1, or an unset legacy sighting) still reads in the singular.
	for _, single := range [][]rogueSighting{
		{{Server: "10.0.0.254", Iface: "eth0", Count: 1}},
		{{Server: "10.0.0.254", Iface: "eth0"}}, // Count 0 (unset) counts as one
	} {
		if got := rogueAlertTitle(single); got != "Rogue DHCP server detected" {
			t.Errorf("single-server title = %q, want singular", got)
		}
	}
}

// TestResumeReloadFailureReArmsStandDown proves the dangerous resume path is not silent:
// when the background Kea reload fails after the flag was cleared (Kea still running the
// holdoff, serving nothing), the flag is re-armed so the stood-down banner + Resume
// return - the operator is never left with a green UI over a dark box.
func TestResumeReloadFailureReArmsStandDown(t *testing.T) {
	s, _ := newTestServer(t)
	seedActiveProfile(t, s)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}
	// Start stood down, then resume. The reload fails against the unreachable dev Kea.
	if err := s.sqlite.SetState(dhcpStandDownKey, "1"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if !s.beginReconcile() {
		t.Fatal("could not claim the reconcile guard")
	}
	if err := s.setStandDown("admin", false, ""); err != nil {
		s.endReconcile()
		t.Fatalf("resume: %v", err)
	}
	if s.dhcpStoodDown() {
		t.Fatal("flag should be cleared immediately after resume, before the reload")
	}
	s.scheduleServingReloadHeld("rogue-resume", true) // background; re-arms on failure
	waitGuardReleased(t, s)

	if !s.dhcpStoodDown() {
		t.Error("a failed resume reload must re-arm the stand-down flag (dark box, green UI otherwise)")
	}
	if got := auditActions(t, s); !got["RECONCILE_FAILED"] {
		t.Errorf("a failed resume reload should audit RECONCILE_FAILED, saw %v", got)
	}
}

// TestStandDownReloadFailureClearsFlag proves the stand-down path is hardened symmetrically
// to resume: when the background Kea reload FAILS after the flag was set, Kea is still
// serving the profile, so the flag must be cleared back (not left asserting "stood down"
// over a running server) and the failure audited - the operator never sees "stood down"
// while Kea serves.
func TestStandDownReloadFailureClearsFlag(t *testing.T) {
	s, _ := newTestServer(t)
	seedActiveProfile(t, s)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}

	if !s.beginReconcile() {
		t.Fatal("could not claim the reconcile guard")
	}
	if err := s.setStandDown("admin", true, "192.0.2.7"); err != nil {
		s.endReconcile()
		t.Fatalf("stand down: %v", err)
	}
	if !s.dhcpStoodDown() {
		t.Fatal("flag should be set immediately after stand down, before the reload")
	}
	s.scheduleServingReloadHeld("rogue-standdown", false) // background; the reload fails against dev Kea
	waitGuardReleased(t, s)

	if s.dhcpStoodDown() {
		t.Error("a failed stand-down reload must clear the flag back (Kea still serving; must not assert stood down)")
	}
	if got := auditActions(t, s); !got["RECONCILE_FAILED"] {
		t.Errorf("a failed stand-down reload should audit RECONCILE_FAILED, saw %v", got)
	}
}

// TestKeaConfigForStateHoldoffVsProfile proves the state-aware renderer: while stood
// down it emits the holdoff (empty subnet4, no served pool); cleared, it emits the
// active profile's subnets.
func TestKeaConfigForStateHoldoffVsProfile(t *testing.T) {
	s, _ := newTestServer(t)
	seedActiveProfile(t, s)
	scopes, err := s.loadScopeConfigs(0)
	if err != nil || len(scopes) == 0 {
		t.Fatalf("load scopes: %v (n=%d)", err, len(scopes))
	}

	_ = s.sqlite.SetState(dhcpStandDownKey, "1")
	holdoff, err := s.keaConfigForState(scopes)
	if err != nil {
		t.Fatalf("holdoff render: %v", err)
	}
	if !strings.Contains(holdoff, `"subnet4": []`) {
		t.Errorf("holdoff config should serve no subnet:\n%s", holdoff)
	}
	if strings.Contains(holdoff, "10.0.0.0/24") {
		t.Errorf("holdoff config must not carry the profile subnet:\n%s", holdoff)
	}

	_ = s.sqlite.SetState(dhcpStandDownKey, "0")
	serving, err := s.keaConfigForState(scopes)
	if err != nil {
		t.Fatalf("profile render: %v", err)
	}
	if !strings.Contains(serving, `"subnet": "10.0.0.0/24"`) {
		t.Errorf("serving config should carry the profile subnet:\n%s", serving)
	}
}

// TestReconcileActiveHonorsStandDown proves the boot/reconcile path renders the holdoff
// config while the flag is set, so a reboot mid-conflict does not silently resume
// serving. The reload fails against the unreachable dev Kea, but the config is written
// to disk first - which is what we assert.
func TestReconcileActiveHonorsStandDown(t *testing.T) {
	s, _ := newTestServer(t)
	seedActiveProfile(t, s)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}
	if err := s.sqlite.SetState(dhcpStandDownKey, "1"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	// Reload fails against the dev Kea (expected); the written conf is the assertion.
	_ = s.reconcileActive(ModeConverge, 0)

	conf, err := os.ReadFile(filepath.Join(s.cfg.KeaConfDir, "kea-dhcp4.conf"))
	if err != nil {
		t.Fatalf("read written kea conf: %v", err)
	}
	if !strings.Contains(string(conf), `"subnet4": []`) {
		t.Errorf("stood-down reconcile should write the holdoff (no subnet):\n%s", conf)
	}
	if strings.Contains(string(conf), "10.0.0.0/24") {
		t.Errorf("stood-down reconcile must not serve the profile subnet:\n%s", conf)
	}
}

// TestSetStandDownPersistsFlagAndAudits covers the split-out DB mutation: standing down
// persists the flag and audits ROGUE_STANDDOWN; resuming clears it and audits
// ROGUE_RESUME.
func TestSetStandDownPersistsFlagAndAudits(t *testing.T) {
	s, _ := newTestServer(t)

	if err := s.setStandDown("admin", true, "192.0.2.7 (aa:bb:cc:dd:ee:ff)"); err != nil {
		t.Fatalf("stand down: %v", err)
	}
	if !s.dhcpStoodDown() {
		t.Error("flag should be set after stand down")
	}
	if got := auditActions(t, s); !got["ROGUE_STANDDOWN"] {
		t.Errorf("stand down did not audit ROGUE_STANDDOWN, saw %v", got)
	}

	if err := s.setStandDown("admin", false, ""); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if s.dhcpStoodDown() {
		t.Error("flag should be cleared after resume")
	}
	if got := auditActions(t, s); !got["ROGUE_RESUME"] {
		t.Errorf("resume did not audit ROGUE_RESUME, saw %v", got)
	}
}

// TestStandDownHandlerCSRFAndFlag drives the real handler through lifecycleMiddleware: a
// token-less POST is rejected (CSRF), and a valid authenticated POST persists the flag
// and audits. The background Kea reload is joined before the DB is torn down.
func TestStandDownHandlerCSRFAndFlag(t *testing.T) {
	s, _ := newTestServer(t)
	seedAdmin(t, s, "pw")
	seedActiveProfile(t, s)
	if err := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}
	sid, err := s.createSession("admin")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	_, csrf, _, ok := s.sessionUser(sid)
	if !ok || csrf == "" {
		t.Fatal("expected a session csrf token")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /rogue/standdown", s.handleStandDown)
	h := s.lifecycleMiddleware(mux)

	post := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/rogue/standdown", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// No CSRF token: rejected by the middleware, handler never runs.
	if rr := post(url.Values{}); rr.Code != http.StatusForbidden {
		t.Errorf("token-less stand-down: status=%d want 403", rr.Code)
	}
	if s.dhcpStoodDown() {
		t.Fatal("token-less request must not have stood DHCP down")
	}

	// Valid token: reaches the handler, persists the flag, redirects back.
	rr := post(url.Values{"csrf_token": {csrf}})
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Errorf("valid stand-down: status=%d want a redirect", rr.Code)
	}
	if !s.dhcpStoodDown() {
		t.Error("valid stand-down did not persist the flag")
	}
	if got := auditActions(t, s); !got["ROGUE_STANDDOWN"] {
		t.Errorf("handler did not audit ROGUE_STANDDOWN, saw %v", got)
	}
	// Join the background reload goroutine (it releases the guard on completion) so its
	// audit write can't race the test's DB teardown.
	waitGuardReleased(t, s)
}

// auditActions returns the set of audit_log actions recorded so far.
func auditActions(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	rows, err := s.sqlite.Query("SELECT action FROM audit_log")
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[a] = true
	}
	return out
}

// waitGuardReleased blocks until the background reconcile guard is released (or a short
// timeout), so a detached reload goroutine finishes its DB writes before teardown.
func waitGuardReleased(t *testing.T, s *Server) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if !s.applying.Load() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background reload guard was never released")
}
