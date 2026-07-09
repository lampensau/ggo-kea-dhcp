package web

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// withCurrentVersion pins the running-version var for a test.
func withCurrentVersion(t *testing.T, v string) {
	t.Helper()
	prev := updateCurrentVersion
	updateCurrentVersion = v
	t.Cleanup(func() { updateCurrentVersion = prev })
}

func TestStageUpdate(t *testing.T) {
	payload := []byte("not really a deb, but bytes are bytes")
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	s, _ := newUpdateTestServer(t, nil)

	// Good hash: staged file + manifest land, no partial remains.
	if err := s.stageUpdate("9.9.9", "app", ts.URL+"/deb", good, "admin"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	staged, err := os.ReadFile(filepath.Join(s.updateDir, updateStagedDeb))
	if err != nil || string(staged) != string(payload) {
		t.Fatalf("staged deb wrong: %v", err)
	}
	man := s.readUpdateManifest()
	if man == nil || man.Version != "9.9.9" || man.Scope != "app" || man.SHA256 != good || man.RequestedBy != "admin" {
		t.Fatalf("manifest wrong: %+v", man)
	}
	if !strings.HasPrefix(man.Deb, s.updateDir) {
		t.Fatalf("manifest deb path outside staging dir: %q", man.Deb)
	}
	if _, err := os.Stat(filepath.Join(s.updateDir, updateStagedDeb+".partial")); !os.IsNotExist(err) {
		t.Fatal("partial must not remain after a successful stage")
	}

	// Bad hash: refused, partial cleaned up, staged deb from the previous good
	// run untouched.
	if err := s.stageUpdate("9.9.9", "app", ts.URL+"/deb", strings.Repeat("0", 64), "admin"); err == nil {
		t.Fatal("bad hash must refuse to stage")
	} else if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.updateDir, updateStagedDeb+".partial")); !os.IsNotExist(err) {
		t.Fatal("partial must be removed after a hash mismatch")
	}
	if cur, _ := os.ReadFile(filepath.Join(s.updateDir, updateStagedDeb)); string(cur) != string(payload) {
		t.Fatal("a failed re-stage must not clobber the previously staged package")
	}

	// Download error (non-200): refused.
	if err := s.stageUpdate("9.9.9", "app", ts.URL+"/gone", good, "admin"); err == nil {
		t.Fatal("a failed download must refuse to stage")
	}
}

// installForm posts /update/install with the given fields through the handler
// directly (routing/CSRF are middleware concerns covered elsewhere).
func installForm(s *Server, fields url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/update/install", strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleUpdateInstall(w, req)
	return w
}

func TestUpdateInstallGuardChain(t *testing.T) {
	withCurrentVersion(t, "1.0.0")
	payload := []byte("deb bytes")
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	newInstallServer := func(t *testing.T) *Server {
		s, _ := newUpdateTestServer(t, nil)
		seedAdmin(t, s, "correct horse battery staple")
		_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateActive)
		_ = s.sqlite.SetStates(map[string]string{
			stateUpdateVersion: "2.0.0",
			stateUpdateScope:   "app",
			stateUpdateSHA256:  good,
			stateUpdateDebURL:  ts.URL + "/deb",
		})
		return s
	}
	okForm := url.Values{"current_password": {"correct horse battery staple"}, "version": {"2.0.0"}}
	guardsFree := func(t *testing.T, s *Server) {
		t.Helper()
		if s.updating.Load() || s.recon.IsApplying() {
			t.Fatal("a refused install must not leave a guard held")
		}
	}

	t.Run("wrong password refused", func(t *testing.T) {
		s := newInstallServer(t)
		installForm(s, url.Values{"current_password": {"nope"}, "version": {"2.0.0"}})
		guardsFree(t, s)
		if countAudit(t, s, "UPDATE_INSTALL") != 1 {
			t.Fatal("refusal must be audited")
		}
	})

	t.Run("not ACTIVE refused", func(t *testing.T) {
		s := newInstallServer(t)
		_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding)
		installForm(s, okForm)
		guardsFree(t, s)
	})

	t.Run("stale version refused", func(t *testing.T) {
		s := newInstallServer(t)
		installForm(s, url.Values{"current_password": {"correct horse battery staple"}, "version": {"1.5.0"}})
		guardsFree(t, s)
		if _, err := os.Stat(filepath.Join(s.updateDir, updateStagedDeb)); !os.IsNotExist(err) {
			t.Fatal("a refused install must not stage anything")
		}
	})

	t.Run("no digest refused", func(t *testing.T) {
		s := newInstallServer(t)
		_ = s.sqlite.SetState(stateUpdateSHA256, "")
		installForm(s, okForm)
		guardsFree(t, s)
	})

	t.Run("system scope without needs_system refused", func(t *testing.T) {
		s := newInstallServer(t)
		f := url.Values{"current_password": {"correct horse battery staple"}, "version": {"2.0.0"}, "scope": {"system"}}
		installForm(s, f)
		guardsFree(t, s)
	})

	t.Run("double submit refused by updating CAS", func(t *testing.T) {
		s := newInstallServer(t)
		s.updating.Store(true)
		installForm(s, okForm)
		if s.recon.IsApplying() {
			t.Fatal("the loser of the updating CAS must not claim the apply guard")
		}
		s.updating.Store(false)
	})

	t.Run("in-flight apply refused, updating released", func(t *testing.T) {
		s := newInstallServer(t)
		if !s.beginReconcile() {
			t.Fatal("claim apply guard")
		}
		installForm(s, okForm)
		if s.updating.Load() {
			t.Fatal("losing the apply guard must release the updating CAS")
		}
		s.endReconcile()
	})

	t.Run("happy path stages, holds guards, responds interstitial", func(t *testing.T) {
		s := newInstallServer(t)
		w := installForm(s, okForm)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Installing update") {
			t.Fatalf("expected the polling interstitial, got %d: %.120s", w.Code, w.Body.String())
		}
		if !s.updating.Load() || !s.recon.IsApplying() {
			t.Fatal("a triggered install must hold both guards")
		}
		if _, err := os.Stat(filepath.Join(s.updateDir, updateStagedDeb)); err != nil {
			t.Fatalf("deb not staged: %v", err)
		}
		man := s.readUpdateManifest()
		if man == nil || man.Version != "2.0.0" || man.Scope != "app" {
			t.Fatalf("manifest wrong: %+v", man)
		}
		var res string
		if err := s.sqlite.QueryRow("SELECT result FROM audit_log WHERE action='UPDATE_INSTALL' ORDER BY id DESC LIMIT 1").Scan(&res); err != nil || res != "SUCCESS" {
			t.Fatalf("expected an UPDATE_INSTALL SUCCESS audit, got %q err=%v", res, err)
		}
		// An apply attempted mid-update is refused with the update-specific message.
		// A VALID candidate, so the refusal provably comes from the updating check
		// (which sits after render+validate), not from a validation error.
		scopes := []ScopeConfig{{CIDR: "10.0.0.0/24", Preset: "generic"}}
		scopes[0].Plan = seedDefaultPlan(scopes[0])
		if _, err := s.beginApply("p", scopes, UplinkConfig{}); err == nil || !strings.Contains(err.Error(), "software update") {
			t.Fatalf("beginApply during an update: %v", err)
		}
		s.releaseUpdateGuards()
	})
}

func TestReconcileUpdateResultTable(t *testing.T) {
	withCurrentVersion(t, "2.0.0")

	write := func(t *testing.T, s *Server, name, content string) {
		t.Helper()
		if err := os.MkdirAll(s.updateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.updateDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(s *Server, name string) bool {
		_, err := os.Stat(filepath.Join(s.updateDir, name))
		return err == nil
	}
	manifest := `{"schema":1,"version":"2.0.0","scope":"app","sha256":"ab","deb":"/x","requested_by":"admin"}`

	t.Run("result ok matching version audits APPLIED once and cleans up", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		write(t, s, updateManifestFile, manifest)
		write(t, s, updateStagedDeb, "deb")
		write(t, s, updateResultFile, `{"version":"2.0.0","status":"ok","detail":""}`)
		s.reconcileUpdateResult()
		if countAudit(t, s, "UPDATE_APPLIED") != 1 {
			t.Fatal("expected one UPDATE_APPLIED")
		}
		if exists(s, updateStagedDeb) || exists(s, updateManifestFile) || exists(s, updateResultFile) {
			t.Fatal("success must clean the staging directory")
		}
		// Idempotent across a second boot (late-arriving result.json).
		write(t, s, updateResultFile, `{"version":"2.0.0","status":"ok","detail":""}`)
		s.reconcileUpdateResult()
		if countAudit(t, s, "UPDATE_APPLIED") != 1 {
			t.Fatal("UPDATE_APPLIED must not be audited twice for one version")
		}
	})

	t.Run("result ok with version mismatch audits FAILED", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		write(t, s, updateResultFile, `{"version":"3.0.0","status":"ok","detail":""}`)
		s.reconcileUpdateResult()
		if countAudit(t, s, "UPDATE_FAILED") != 1 || countAudit(t, s, "UPDATE_APPLIED") != 0 {
			t.Fatal("an ok result for a version that is not running must audit FAILED")
		}
	})

	t.Run("needs_system latches and keeps the staged deb", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		write(t, s, updateManifestFile, `{"schema":1,"version":"3.0.0","scope":"app","sha256":"ab","deb":"/x","requested_by":"admin"}`)
		write(t, s, updateStagedDeb, "deb")
		write(t, s, updateResultFile, `{"version":"3.0.0","status":"needs_system","detail":"deps"}`)
		s.reconcileUpdateResult()
		if ns, _ := s.sqlite.GetState(stateUpdateNeedsSystem); ns != "1" {
			t.Fatal("needs_system must latch")
		}
		if countAudit(t, s, "UPDATE_FAILED") != 1 {
			t.Fatal("needs_system must be audited as UPDATE_FAILED")
		}
		if !exists(s, updateStagedDeb) || !exists(s, updateManifestFile) {
			t.Fatal("needs_system must keep the staged package")
		}
		if exists(s, updateResultFile) {
			t.Fatal("the processed result must be consumed")
		}
	})

	t.Run("failed audits and cleans staging", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		write(t, s, updateManifestFile, `{"schema":1,"version":"3.0.0","scope":"app","sha256":"ab","deb":"/x","requested_by":"admin"}`)
		write(t, s, updateStagedDeb, "deb")
		write(t, s, updateResultFile, `{"version":"3.0.0","status":"failed","detail":"boom"}`)
		s.reconcileUpdateResult()
		if countAudit(t, s, "UPDATE_FAILED") != 1 {
			t.Fatal("failed result must audit UPDATE_FAILED")
		}
		if exists(s, updateStagedDeb) || exists(s, updateManifestFile) || exists(s, updateResultFile) {
			t.Fatal("a failed install must clean the staging directory")
		}
	})

	t.Run("no result but manifest matches running version = the success race", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		write(t, s, updateManifestFile, manifest)
		write(t, s, updateStagedDeb, "deb")
		s.reconcileUpdateResult()
		if countAudit(t, s, "UPDATE_APPLIED") != 1 {
			t.Fatal("running the staged version proves the update landed")
		}
		if exists(s, updateStagedDeb) || exists(s, updateManifestFile) {
			t.Fatal("confirmed update must clean the staging directory")
		}
	})

	t.Run("malformed result with matching manifest folds via manifest and clears the leftover", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		write(t, s, updateManifestFile, manifest)
		write(t, s, updateStagedDeb, "deb")
		write(t, s, updateResultFile, `{not valid json`)
		s.reconcileUpdateResult()
		if countAudit(t, s, "UPDATE_APPLIED") != 1 {
			t.Fatal("a malformed result must not block folding the confirmed update via the manifest")
		}
		if exists(s, updateStagedDeb) || exists(s, updateManifestFile) || exists(s, updateResultFile) {
			t.Fatal("the malformed result.json and staged package must be cleared")
		}
	})

	t.Run("stale manifest for another version is discarded", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		write(t, s, updateManifestFile, `{"schema":1,"version":"9.9.9","scope":"app","sha256":"ab","deb":"/x","requested_by":"admin"}`)
		write(t, s, updateStagedDeb, "deb")
		write(t, s, updateStagedDeb+".partial", "half")
		s.reconcileUpdateResult()
		if exists(s, updateStagedDeb) || exists(s, updateManifestFile) || exists(s, updateStagedDeb+".partial") {
			t.Fatal("stale staging must be cleared on boot")
		}
		if countAudit(t, s, "UPDATE_APPLIED") != 0 {
			t.Fatal("stale staging must not claim success")
		}
	})

	t.Run("empty staging dir is a no-op", func(t *testing.T) {
		s, _ := newUpdateTestServer(t, nil)
		s.reconcileUpdateResult()
		if countAudit(t, s, "UPDATE_APPLIED")+countAudit(t, s, "UPDATE_FAILED") != 0 {
			t.Fatal("nothing staged, nothing audited")
		}
	})
}
