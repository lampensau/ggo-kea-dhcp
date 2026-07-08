package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// updater.sh anchors update authenticity in GitHub's published digest, re-fetched as
// root and compared against the staged .deb, failing closed if that digest is absent,
// unreachable, or mismatched. That gate is the one thing an app-user compromise cannot
// forge, so its fail-closed behavior is what most needs a behavioral test - shellcheck
// only proves syntax. These tests drive the real script through its GGO_UPDATE_STAGE /
// GGO_UPDATE_API / GGO_UPDATE_REPO validation seams against a fake releases API, with
// dpkg/apt stubbed on PATH so nothing touches the host. This is the CI-runnable half of
// issue #29; the full live-GitHub run on the Pi remains a manual owner task.

// updaterTestDeb is the fake package the harness stages; its sha256 is what a matching
// published digest must advertise.
const updaterTestDeb = "fake package bytes for v9.9.9"

func updaterTestDebSHA() string {
	sum := sha256.Sum256([]byte(updaterTestDeb))
	return hex.EncodeToString(sum[:])
}

func updaterScriptPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	p := filepath.Join(filepath.Dir(thisFile), "..", "..", "packaging", "scripts", "updater.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("updater.sh not found at %s: %v", p, err)
	}
	return p
}

// stubBin writes a PATH directory of shell stubs so the script's dpkg/apt calls succeed
// without a real package system: dpkg-deb reports the expected package name, the rest are
// no-op successes, and dpkg-query reports "not installed" so the downgrade guard allows.
func stubBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	stubs := map[string]string{
		"dpkg":       "#!/bin/sh\nexit 0\n",                    // --configure -a
		"apt-get":    "#!/bin/sh\nexit 0\n",                    // update / install -y
		"dpkg-query": "#!/bin/sh\nexit 0\n",                    // -W -> empty output = not installed
		"dpkg-deb":   "#!/bin/sh\necho ggo-kea-dhcp\nexit 0\n", // -f DEB Package
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type updaterResult struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
}

// runUpdater stages a fake package + manifest, points the script at apiURL, runs it with
// dpkg/apt stubbed, and returns the parsed result.json.
func runUpdater(t *testing.T, apiURL string) updaterResult {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("updater.sh harness runs on linux only")
	}
	for _, tool := range []string{"sh", "jq", "curl", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("required tool %q not available", tool)
		}
	}

	stage := t.TempDir()
	debPath := filepath.Join(stage, "pkg.deb")
	if err := os.WriteFile(debPath, []byte(updaterTestDeb), 0o644); err != nil {
		t.Fatal(err)
	}

	man, _ := json.Marshal(updateStageManifest{
		Schema: 1, Version: "9.9.9", Scope: "app", SHA256: updaterTestDebSHA(), Deb: debPath, RequestedBy: "admin",
	})
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), man, 0o644); err != nil {
		t.Fatal(err)
	}

	env := append(os.Environ(),
		"PATH="+stubBin(t)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GGO_UPDATE_STAGE="+stage,
		"GGO_UPDATE_API="+apiURL,
		"GGO_UPDATE_REPO=example/scratch",
	)
	cmd := exec.Command("sh", updaterScriptPath(t))
	cmd.Env = env
	out, _ := cmd.CombinedOutput() // non-zero exit is expected on the fail-closed paths

	data, err := os.ReadFile(filepath.Join(stage, "result.json"))
	if err != nil {
		t.Fatalf("no result.json written (script output: %s): %v", out, err)
	}
	var res updaterResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("result.json not JSON (%q): %v", data, err)
	}
	return res
}

// fakeReleaseAPI serves the releases/tags response the script fetches. digest "" omits
// the field; the asset name matches the ASSET the script looks for.
func fakeReleaseAPI(t *testing.T, digest string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/releases/tags/v9.9.9") {
			http.NotFound(w, r)
			return
		}
		asset := `{"name":"ggo-kea-dhcp_arm64.deb"`
		if digest != "" {
			asset += fmt.Sprintf(`,"digest":%q`, digest)
		}
		asset += `}`
		_, _ = fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":[%s]}`, asset)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUpdaterDigestGateMatchInstalls(t *testing.T) {
	// The published digest matches the staged .deb: the gate passes and the (stubbed)
	// install reports success.
	api := fakeReleaseAPI(t, "sha256:"+updaterTestDebSHA())

	res := runUpdater(t, api.URL)
	if res.Status != "ok" {
		t.Fatalf("status = %q detail = %q, want ok (matching digest should install)", res.Status, res.Detail)
	}
}

func TestUpdaterDigestGateMismatchFailsClosed(t *testing.T) {
	// The published digest is for a different artifact than what is staged: the install
	// must be refused, not fall back to the app-written sha.
	api := fakeReleaseAPI(t, "sha256:"+strings.Repeat("0", 64))

	res := runUpdater(t, api.URL)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed on a digest mismatch", res.Status)
	}
	if !strings.Contains(res.Detail, "does not match") {
		t.Fatalf("detail = %q, want a digest-mismatch message", res.Detail)
	}
}

func TestUpdaterDigestGateUnreachableFailsClosed(t *testing.T) {
	// GitHub unreachable: the authoritative digest cannot be fetched, so the install must
	// fail closed rather than trust the app-written sha.
	res := runUpdater(t, "http://127.0.0.1:1")
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed when the digest API is unreachable", res.Status)
	}
	if !strings.Contains(res.Detail, "cannot reach GitHub") {
		t.Fatalf("detail = %q, want an unreachable-API message", res.Detail)
	}
}

func TestUpdaterDigestGateNoPublishedDigestFailsClosed(t *testing.T) {
	// The release exists but publishes no digest for the asset: fail closed, never
	// silently install on the app sha alone.
	api := fakeReleaseAPI(t, "")

	res := runUpdater(t, api.URL)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed when no digest is published", res.Status)
	}
	if !strings.Contains(res.Detail, "no verifiable digest") {
		t.Fatalf("detail = %q, want a no-digest message", res.Detail)
	}
}
