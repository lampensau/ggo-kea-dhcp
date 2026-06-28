package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var semver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// TestNumberIsSemver guards that the committed version is the X.Y.Z shape the
// release tooling requires: `make release` sets it, and release.yml's tag-match
// guard reads it back to compare against the git tag.
func TestNumberIsSemver(t *testing.T) {
	if !semver.MatchString(Number) {
		t.Fatalf("version.Number = %q, want X.Y.Z", Number)
	}
}

// TestReleaseBumpRoundTrip runs the actual sed commands used by the `make
// release` target (to set Number) and .github/workflows/release.yml's tag guard
// (to extract it back), and asserts they round-trip. If either sed drifts so a
// release would ship a version the CI guard can't read back, this fails. Keep
// the two sed strings below in sync with the Makefile / release.yml.
func TestReleaseBumpRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("sed"); err != nil {
		t.Skip("sed not available")
	}
	const want = "9.8.7"
	f := filepath.Join(t.TempDir(), "version.go")
	if err := os.WriteFile(f, []byte(`const Number = "0.0.0"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Makefile `release` target - bump Number to the new version.
	if out, err := exec.Command("sed", "-i", `s/Number = ".*"/Number = "`+want+`"/`, f).CombinedOutput(); err != nil {
		t.Fatalf("bump sed: %v: %s", err, out)
	}

	// release.yml tag-match guard - extract Number back out.
	out, err := exec.Command("sed", "-n", `s/.*Number = "\(.*\)".*/\1/p`, f).Output()
	if err != nil {
		t.Fatalf("extract sed: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("round-trip: bumped to %q, extracted %q", want, got)
	}
}
