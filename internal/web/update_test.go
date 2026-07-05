package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/db"
)

func TestParseSemverAndOrdering(t *testing.T) {
	cases := []struct {
		a, b  string
		newer bool // semverNewer(a, b)
	}{
		{"1.1.3", "1.1.2", true},
		{"v1.1.3", "1.1.2", true},
		{"1.2.0", "1.1.9", true},
		{"2.0.0", "1.99.99", true},
		{"1.1.2", "1.1.2", false},
		{"1.1.1", "1.1.2", false},   // downgrade never offered
		{"1.1", "1.1.2", false},     // malformed = not newer
		{"1.1.2.4", "1.1.2", false}, // malformed = not newer
		{"abc", "1.1.2", false},
		{"", "1.1.2", false},
		{"1.1.3", "garbage", false}, // malformed current = never claim newer
		{"1.1.-3", "1.1.2", false},
		{"10.0.0", "9.9.9", true},
	}
	for _, c := range cases {
		if got := semverNewer(c.a, c.b); got != c.newer {
			t.Errorf("semverNewer(%q, %q) = %v, want %v", c.a, c.b, got, c.newer)
		}
	}
}

func TestReleaseFixtureDecode(t *testing.T) {
	// The shape GitHub's releases/latest actually returns (trimmed): the asset
	// digest carries the sha256: prefix install.sh already consumes, and a release
	// may or may not ship a release.json manifest asset.
	fixture := `{
		"tag_name": "v9.9.9",
		"body": "## Changes\r\n- one\r\n- two",
		"assets": [
			{"name": "ggo-kea-dhcp_arm64.deb", "digest": "sha256:ab12", "browser_download_url": "https://example.invalid/deb"},
			{"name": "ggo-kea-dhcp-arm64", "digest": "sha256:cd34", "browser_download_url": "https://example.invalid/bin"}
		]
	}`
	var rel ghRelease
	if err := json.Unmarshal([]byte(fixture), &rel); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rel.TagName != "v9.9.9" || len(rel.Assets) != 2 {
		t.Fatalf("unexpected decode: %+v", rel)
	}
	if !strings.HasPrefix(rel.Assets[0].Digest, "sha256:") {
		t.Fatalf("digest prefix lost: %q", rel.Assets[0].Digest)
	}
	// No release.json asset -> scope must default to app without any HTTP call.
	s, _ := newUpdateTestServer(t, nil)
	if scope := s.fetchReleaseScope(&rel); scope != "app" {
		t.Fatalf("missing manifest should mean scope app, got %q", scope)
	}
}

// newUpdateTestServer wires the update checker onto the reconciler test server:
// a temp SQLite DB plus an httptest release API (handler nil = an unreachable
// endpoint, for the connection-refused paths).
func newUpdateTestServer(t *testing.T, handler http.Handler) (*Server, *httptest.Server) {
	t.Helper()
	s, _ := newTestServer(t)
	s.updateHTTP = newUpdateHTTPClient()
	s.updateDir = t.TempDir()
	if handler == nil {
		s.updateAPIBase = "http://127.0.0.1:1" // nothing listens here
		return s, nil
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	s.updateAPIBase = ts.URL
	return s, ts
}

// releaseAPI serves a fake GitHub releases/latest (and the release asset
// downloads) and counts requests.
type releaseAPI struct {
	status   int // releases/latest status (0 = 200)
	tag      string
	body     string
	digest   string // deb asset digest ("" = no digest published)
	manifest string // release.json content ("" = no manifest asset)
	hits     atomic.Int64
}

func (a *releaseAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.hits.Add(1)
	switch {
	case strings.HasSuffix(r.URL.Path, "/releases/latest"):
		if a.status != 0 && a.status != http.StatusOK {
			w.WriteHeader(a.status)
			return
		}
		base := "http://" + r.Host
		rel := ghRelease{TagName: a.tag, Body: a.body}
		rel.Assets = append(rel.Assets, ghAsset{Name: updateDebAsset, Digest: a.digest, DownloadURL: base + "/dl/deb"})
		if a.manifest != "" {
			rel.Assets = append(rel.Assets, ghAsset{Name: updateManifestAsset, DownloadURL: base + "/dl/manifest"})
		}
		_ = json.NewEncoder(w).Encode(rel)
	case r.URL.Path == "/dl/manifest":
		fmt.Fprint(w, a.manifest)
	default:
		http.NotFound(w, r)
	}
}

func countAudit(t *testing.T, s *Server, action string) int {
	t.Helper()
	var n int
	if err := s.sqlite.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = ?", action).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func TestCheckForUpdateStateMachine(t *testing.T) {
	api := &releaseAPI{tag: "v9.9.9", body: "notes", digest: "sha256:ab12",
		manifest: `{"schema":1,"version":"9.9.9","scope":"system"}`}
	s, _ := newUpdateTestServer(t, api)
	mustState := func(key, want string) {
		t.Helper()
		if got, _ := s.sqlite.GetState(key); got != want {
			t.Errorf("state %s = %q, want %q", key, got, want)
		}
	}

	// ONBOARDING: a background check makes zero requests.
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding)
	if newer, err := s.checkForUpdate(false); newer || err != nil {
		t.Fatalf("onboarding check: newer=%v err=%v", newer, err)
	}
	if api.hits.Load() != 0 {
		t.Fatalf("onboarding check must not hit the network (%d requests)", api.hits.Load())
	}

	// ACTIVE: newer release found, persisted, audited once.
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)
	if newer, err := s.checkForUpdate(false); !newer || err != nil {
		t.Fatalf("active check: newer=%v err=%v", newer, err)
	}
	mustState(stateUpdateVersion, "9.9.9")
	mustState(stateUpdateScope, "system")
	mustState(stateUpdateSHA256, "ab12")
	mustState(stateUpdateNotified, "9.9.9")
	if got := countAudit(t, s, "UPDATE_AVAILABLE"); got != 1 {
		t.Fatalf("UPDATE_AVAILABLE audited %d times, want 1", got)
	}
	if !s.updateBadgeView().Show {
		t.Fatal("badge should show for a newer release")
	}

	// Second check of the same version: no second audit row (persisted latch).
	if _, err := s.checkForUpdate(false); err != nil {
		t.Fatalf("second check: %v", err)
	}
	if got := countAudit(t, s, "UPDATE_AVAILABLE"); got != 1 {
		t.Fatalf("second check re-audited (%d rows)", got)
	}

	// Equal version: the stored release clears and the badge goes quiet.
	api.tag = "v" + updateCurrentVersion
	if newer, err := s.checkForUpdate(false); newer || err != nil {
		t.Fatalf("equal-version check: newer=%v err=%v", newer, err)
	}
	mustState(stateUpdateVersion, "")
	mustState(stateUpdateSHA256, "")
	if s.updateBadgeView().Show {
		t.Fatal("badge must clear once the box is current")
	}

	// 403: a backoff is recorded and the next background check is a no-op.
	api.status = http.StatusForbidden
	if _, err := s.checkForUpdate(false); err == nil {
		t.Fatal("403 should surface as an error to the caller")
	}
	if until, _ := s.sqlite.GetState(stateUpdateBackoffUntil); until == "" {
		t.Fatal("403 must record a backoff")
	}
	before := api.hits.Load()
	if _, err := s.checkForUpdate(false); err != nil {
		t.Fatalf("backed-off check should be silent: %v", err)
	}
	if api.hits.Load() != before {
		t.Fatal("backed-off background check must not hit the network")
	}
}

func TestCheckForUpdateRefusedConnectionIsSilent(t *testing.T) {
	s, _ := newUpdateTestServer(t, nil) // nothing listens
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)
	if newer, err := s.checkForUpdate(false); newer || err == nil {
		t.Fatalf("refused connection: newer=%v err=%v", newer, err)
	}
	if v, _ := s.sqlite.GetState(stateUpdateVersion); v != "" {
		t.Fatal("a failed check must not write release state")
	}
	if got := countAudit(t, s, "UPDATE_AVAILABLE"); got != 0 {
		t.Fatal("a failed check must not audit")
	}
	// The panic-guard wrapper swallows it entirely (silent-by-design path).
	s.updateCheckSafe(false)
}

func TestCheckForUpdateNoDigestMeansNotifyOnly(t *testing.T) {
	api := &releaseAPI{tag: "v9.9.9", body: "notes"} // no digest published
	s, _ := newUpdateTestServer(t, api)
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)
	if newer, err := s.checkForUpdate(false); !newer || err != nil {
		t.Fatalf("check: newer=%v err=%v", newer, err)
	}
	v := s.buildUpdateView("tok")
	if !v.Available || v.CanInstall {
		t.Fatalf("no digest must mean notify-only: %+v", v)
	}
	if v.Scope != "app" {
		t.Fatalf("missing manifest must default scope to app, got %q", v.Scope)
	}
}

func TestUpdateDismiss(t *testing.T) {
	s, _ := newUpdateTestServer(t, nil)
	_ = s.sqlite.SetStates(map[string]string{stateUpdateVersion: "9.9.9"})
	if !s.updateBadgeView().Show {
		t.Fatal("badge should show before dismissal")
	}

	w := httptest.NewRecorder()
	s.handleUpdateDismiss(w, httptest.NewRequest("POST", "/update/dismiss", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("dismiss status = %d", w.Code)
	}
	if s.updateBadgeView().Show {
		t.Fatal("badge must hide after dismissal")
	}
	// The card still shows the release; only the badge is dismissed.
	if v := s.buildUpdateView("tok"); !v.Available || !v.Dismissed {
		t.Fatalf("card should keep showing a dismissed release: %+v", v)
	}

	// A NEWER version resurfaces the badge.
	_ = s.sqlite.SetState(stateUpdateVersion, "9.9.10")
	if !s.updateBadgeView().Show {
		t.Fatal("a newer version must resurface the badge")
	}
}

func TestUpdateBackoffParse(t *testing.T) {
	s, _ := newUpdateTestServer(t, nil)
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)
	// An expired backoff does not suppress checks (they fail on the dead endpoint,
	// which is fine - we only assert the gate opened).
	_ = s.sqlite.SetState(stateUpdateBackoffUntil, time.Now().Add(-time.Minute).Format(time.RFC3339))
	if _, err := s.checkForUpdate(false); err == nil {
		t.Fatal("expired backoff should let the check run (and fail on the dead endpoint)")
	}
}
