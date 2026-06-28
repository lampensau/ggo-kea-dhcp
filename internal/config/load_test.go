package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCleanFlags isolates Load()'s use of the package-global flag set and os.Args
// so the test binary's own flags (-test.*) don't reach Load's flag.Parse, and so a
// second Load doesn't panic on a redefined flag. It restores both on cleanup.
func withCleanFlags(t *testing.T, args []string) {
	t.Helper()
	origArgs := os.Args
	origFS := flag.CommandLine
	t.Cleanup(func() {
		os.Args = origArgs
		flag.CommandLine = origFS
	})
	// ContinueOnError so a stray bad flag returns an error instead of os.Exit.
	flag.CommandLine = flag.NewFlagSet(origArgs[0], flag.ContinueOnError)
	os.Args = args
}

// TestLoadDefaults verifies the flag defaults and explicit overrides parse, using
// a pre-existing kea-secret file so initKeaSecret short-circuits (no ./test-kea-gui
// directory is written into the repo).
func TestLoadDefaults(t *testing.T) {
	tmp := t.TempDir()
	secret := filepath.Join(tmp, "gui-secret")
	if err := os.WriteFile(secret, []byte("deadbeef\n"), 0o600); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	dbPath := filepath.Join(tmp, "appliance.db")

	withCleanFlags(t, []string{"ggo-kea-dhcp", "-kea-secret", secret, "-db", dbPath})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BindAddr != "127.0.0.1:8080" {
		t.Errorf("BindAddr default = %q", cfg.BindAddr)
	}
	if cfg.LeaseLifetime != 1800 {
		t.Errorf("LeaseLifetime default = %d, want 1800", cfg.LeaseLifetime)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel default = %q, want info", cfg.LogLevel)
	}
	if cfg.KeaAPIURL != "http://127.0.0.1:8004" {
		t.Errorf("KeaAPIURL default = %q", cfg.KeaAPIURL)
	}
	if cfg.Check {
		t.Error("Check default = true, want false")
	}
	if cfg.DBPath != dbPath {
		t.Errorf("DBPath override = %q, want %q", cfg.DBPath, dbPath)
	}
	if cfg.KeaSecretPath != secret {
		t.Errorf("KeaSecretPath override = %q, want %q", cfg.KeaSecretPath, secret)
	}
}

// TestLoadOverridesAndSecretRead checks non-default flag values land and that
// GetKeaSecret reads (and trims) the file Load pointed at.
func TestLoadOverridesAndSecretRead(t *testing.T) {
	tmp := t.TempDir()
	secret := filepath.Join(tmp, "gui-secret")
	if err := os.WriteFile(secret, []byte("  token123  \n"), 0o600); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	withCleanFlags(t, []string{
		"ggo-kea-dhcp",
		"-kea-secret", secret,
		"-db", filepath.Join(tmp, "x.db"),
		"-bind", "0.0.0.0:9090",
		"-lease-lifetime", "30",
		"-log-level", "debug",
		"-mariadb-dsn", "u:p@tcp(h:3306)/k",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BindAddr != "0.0.0.0:9090" {
		t.Errorf("BindAddr = %q", cfg.BindAddr)
	}
	if cfg.LeaseLifetime != 30 {
		t.Errorf("LeaseLifetime = %d, want 30", cfg.LeaseLifetime)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.MariaDBDSN != "u:p@tcp(h:3306)/k" {
		t.Errorf("MariaDBDSN = %q", cfg.MariaDBDSN)
	}
	got, err := cfg.GetKeaSecret()
	if err != nil {
		t.Fatalf("GetKeaSecret: %v", err)
	}
	if got != "token123" {
		t.Errorf("GetKeaSecret = %q, want token123 (trimmed)", got)
	}
}

// TestLoadMariaDSNEnvFallback verifies the GGO_MARIADB_DSN env var is used when the
// flag is unset (the systemd unit injects it via EnvironmentFile).
func TestLoadMariaDSNEnvFallback(t *testing.T) {
	tmp := t.TempDir()
	secret := filepath.Join(tmp, "gui-secret")
	if err := os.WriteFile(secret, []byte("abc"), 0o600); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	t.Setenv("GGO_MARIADB_DSN", "envuser:envpass@tcp(envhost:3306)/envdb")

	withCleanFlags(t, []string{"ggo-kea-dhcp", "-kea-secret", secret, "-db", filepath.Join(tmp, "x.db")})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MariaDBDSN != "envuser:envpass@tcp(envhost:3306)/envdb" {
		t.Errorf("MariaDBDSN env fallback = %q", cfg.MariaDBDSN)
	}
}

// TestInitKeaSecretGenerates covers the generation branch every Load test deliberately
// skips by pre-seeding the file: a missing secret path gets a fresh random 32-hex token
// written at 0600.
func TestInitKeaSecretGenerates(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "sub", "gui-secret") // parent dir doesn't exist yet
	c := &Config{KeaSecretPath: secret}
	if err := c.initKeaSecret(); err != nil {
		t.Fatalf("initKeaSecret: %v", err)
	}
	if c.KeaSecretPath != secret {
		t.Errorf("path changed unexpectedly: %q", c.KeaSecretPath)
	}
	got, err := os.ReadFile(secret)
	if err != nil {
		t.Fatalf("read generated secret: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("token len = %d, want 32 hex chars (%q)", len(got), got)
	}
	for _, b := range got {
		if !strings.ContainsRune("0123456789abcdef", rune(b)) {
			t.Fatalf("token has non-hex byte %q in %q", b, got)
			break
		}
	}
}

// TestInitKeaSecretFallback covers the read-only-dir fallback: when the configured
// directory can't be created (here the parent is a file, not a dir), initKeaSecret
// must redirect to ./test-kea-gui/gui-secret. t.Chdir keeps that relative path inside
// a tempdir so the repo isn't polluted.
func TestInitKeaSecretFallback(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	blocker := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	c := &Config{KeaSecretPath: filepath.Join(blocker, "gui-secret")} // MkdirAll(blocker) must fail
	if err := c.initKeaSecret(); err != nil {
		t.Fatalf("initKeaSecret: %v", err)
	}
	wantPath := filepath.Join("./test-kea-gui", "gui-secret")
	if c.KeaSecretPath != wantPath {
		t.Fatalf("fallback path = %q, want %q", c.KeaSecretPath, wantPath)
	}
	if _, err := os.Stat(filepath.Join(tmp, "test-kea-gui", "gui-secret")); err != nil {
		t.Errorf("fallback secret not written: %v", err)
	}
}

// TestParseMariaDSNEdgeCases extends the existing happy-path table with the
// degenerate forms ParseMariaDSN must tolerate (no tcp() wrapper, no creds, no
// dbname, empty input).
func TestParseMariaDSNEdgeCases(t *testing.T) {
	cases := []struct {
		dsn                    string
		host, user, pass, name string
	}{
		{"", "", "", "", ""},
		{"user:pass@host:3306/db", "host", "user", "pass", "db"},      // no tcp() wrapper
		{"user:pass@tcp(host:3306)", "host", "user", "pass", ""},      // no dbname
		{"tcp(host:3306)/db", "host", "", "", "db"},                   // no credentials
		{"host/db", "host", "", "", "db"},                             // bare host, no port, no creds
		{"u:p:withcolon@tcp(h:3306)/k", "h", "u", "p:withcolon", "k"}, // password contains colon
	}
	for _, c := range cases {
		host, user, pass, name := ParseMariaDSN(c.dsn)
		if host != c.host || user != c.user || pass != c.pass || name != c.name {
			t.Errorf("ParseMariaDSN(%q) = (%q,%q,%q,%q), want (%q,%q,%q,%q)",
				c.dsn, host, user, pass, name, c.host, c.user, c.pass, c.name)
		}
	}
}

// TestRedactedMariaDSN confirms the password never appears in the redacted form
// and that empty user/host degrade to "?".
func TestRedactedMariaDSN(t *testing.T) {
	cases := []struct {
		dsn  string
		want string
	}{
		{"kea_user:s3cret@tcp(localhost:3306)/kea", "kea_user@localhost/kea"},
		{"", "?@?/"},
		{"tcp(host:3306)/db", "?@host/db"}, // no user
	}
	for _, c := range cases {
		got := RedactedMariaDSN(c.dsn)
		if got != c.want {
			t.Errorf("RedactedMariaDSN(%q) = %q, want %q", c.dsn, got, c.want)
		}
		// Defense in depth: the literal password must never leak.
		if c.dsn == "kea_user:s3cret@tcp(localhost:3306)/kea" &&
			strings.Contains(got, "s3cret") {
			t.Errorf("redacted DSN leaked the password: %q", got)
		}
	}
}
