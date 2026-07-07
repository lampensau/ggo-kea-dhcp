package config

import (
	"os"
	"path/filepath"
	"testing"
)

// unwritableSecretPath returns a KeaSecretPath whose parent cannot be created
// (a regular file used as the directory -> MkdirAll fails ENOTDIR), so
// initKeaSecret takes the not-writable branch deterministically.
func unwritableSecretPath(t *testing.T) string {
	t.Helper()
	notADir := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(notADir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(notADir, "gui-secret")
}

// TestInitKeaSecretFailsLoudWhenKeaInstalled is the fix: on a real appliance
// (kea-dhcp4 present) a non-writable /etc/kea is a hard error, NOT a silent repoint
// of KeaConfDir to the dev sandbox that would send every rendered kea-dhcp4.conf
// where Kea never reads it.
func TestInitKeaSecretFailsLoudWhenKeaInstalled(t *testing.T) {
	orig := keaInstalled
	keaInstalled = func() bool { return true }
	t.Cleanup(func() { keaInstalled = orig })

	c := &Config{KeaSecretPath: unwritableSecretPath(t), KeaConfDir: "/etc/kea/"}
	if err := c.initKeaSecret(); err == nil {
		t.Fatal("expected a loud error when kea-dhcp4 is installed and the dir is not writable")
	}
	if c.KeaConfDir != "/etc/kea/" {
		t.Errorf("KeaConfDir was silently repointed to %q - it must stay /etc/kea/ and fail loud", c.KeaConfDir)
	}
}

// TestInitKeaSecretFallsBackWhenKeaAbsent proves the dev-sandbox behaviour is
// preserved: with no kea-dhcp4 installed, the same failure repoints to ./test-kea-gui.
func TestInitKeaSecretFallsBackWhenKeaAbsent(t *testing.T) {
	orig := keaInstalled
	keaInstalled = func() bool { return false }
	t.Cleanup(func() { keaInstalled = orig })

	// Contain the ./test-kea-gui the fallback creates inside a temp cwd.
	t.Chdir(t.TempDir())

	c := &Config{KeaSecretPath: unwritableSecretPath(t), KeaConfDir: "/etc/kea/"}
	if err := c.initKeaSecret(); err != nil {
		t.Fatalf("dev fallback should succeed with kea-dhcp4 absent, got: %v", err)
	}
	if c.KeaConfDir != "./test-kea-gui" {
		t.Errorf("dev fallback should repoint KeaConfDir to ./test-kea-gui, got %q", c.KeaConfDir)
	}
	if _, err := os.Stat(filepath.Join("./test-kea-gui", "gui-secret")); err != nil {
		t.Errorf("dev fallback should have written the secret: %v", err)
	}
}
