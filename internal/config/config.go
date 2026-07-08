package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// Config represents the application settings.
type Config struct {
	BindAddr      string
	DBPath        string
	KeaSecretPath string
	KeaConfDir    string
	MariaDBDSN    string
	KeaAPIURL     string
	SnapshotDir   string
	// LeaseLifetime is the active-profile DHCP lease lifetime in seconds (renew at
	// 1/2, rebind at 7/8). Lower = host reservations and pool migrations take effect
	// sooner, at the cost of more renewal traffic and SD-card writes.
	LeaseLifetime int
	// LogLevel is the minimum slog level: debug | info | warn | error.
	LogLevel string
	// Check, when true, runs the preflight prerequisite checks and exits (used by
	// the installer's postinst). Exit 0 = all good, 1 = a hard prerequisite failed.
	Check bool
}

// Load loads the configuration from CLI flags and default values.
func Load() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.BindAddr, "bind", "127.0.0.1:8080", "Address to bind the web server to")
	flag.StringVar(&cfg.DBPath, "db", "./appliance.db", "Path to SQLite database")
	flag.StringVar(&cfg.KeaSecretPath, "kea-secret", "/etc/kea/gui-secret", "Path to Kea HTTP API password file")
	flag.StringVar(&cfg.KeaConfDir, "kea-conf-dir", "/etc/kea/", "Directory where dynamic Kea configs are written")
	// Default empty: production supplies the real DSN (with a per-box random password)
	// via the systemd unit's EnvironmentFile. An empty default means a missing
	// EnvironmentFile fails loudly into degraded mode (no reservations) rather than
	// silently connecting with a known, shipped-in-the-binary credential.
	flag.StringVar(&cfg.MariaDBDSN, "mariadb-dsn", "", "DSN for Kea MariaDB database (e.g. user:pass@tcp(host:3306)/kea)")
	flag.StringVar(&cfg.KeaAPIURL, "kea-api-url", "http://127.0.0.1:8004", "Kea HTTP Control socket endpoint")
	flag.StringVar(&cfg.SnapshotDir, "snapshot-dir", "/var/lib/ggo-kea-dhcp/snapshots", "Directory for Kea config snapshots (user-writable)")
	flag.IntVar(&cfg.LeaseLifetime, "lease-lifetime", 1800, "Active-profile DHCP lease lifetime in seconds (renew at 1/2, rebind at 7/8). Lower = reservations/pool-migrations apply sooner but more renewal traffic + SD writes. Use a small value (e.g. 30) for testing")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log verbosity: debug | info | warn | error")
	flag.BoolVar(&cfg.Check, "check", false, "Run preflight prerequisite checks and exit (0 = all good, 1 = a hard prerequisite failed)")

	flag.Parse()

	// Fall back to the GGO_MARIADB_DSN environment variable when the flag is unset.
	// The systemd unit injects it via EnvironmentFile so the DB password stays out
	// of the process cmdline (where any local user could read it via `ps`).
	if cfg.MariaDBDSN == "" {
		cfg.MariaDBDSN = os.Getenv("GGO_MARIADB_DSN")
	}

	// Ensure the config directory exists; non-fatal if we can't (e.g. running in
	// the current dir without permission to create the parent).
	_ = os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755)

	// Initialize the randomized secure Kea API token if it doesn't exist
	if err := cfg.initKeaSecret(); err != nil {
		return nil, fmt.Errorf("failed to initialize Kea API secret: %w", err)
	}

	return cfg, nil
}

// initKeaSecret ensures the Kea basic auth secret file exists and is populated
// with a random token. If the configured secret directory is not writable, the
// response depends on whether kea-dhcp4 is installed (see fallbackOrFail): a dev
// sandbox redirects BOTH c.KeaSecretPath and c.KeaConfDir to ./test-kea-gui so the
// app still runs; a real appliance returns an error instead of silently sending
// rendered configs to a directory Kea never reads.
func (c *Config) initKeaSecret() error {
	// If the file already exists, we use the existing secret
	if _, err := os.Stat(c.KeaSecretPath); err == nil {
		return nil
	}

	// Generate a secure 32-character hex token
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return err
	}
	token := hex.EncodeToString(bytes)

	// Ensure directory exists
	dir := filepath.Dir(c.KeaSecretPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return c.fallbackOrFail(token, "kea secret dir "+dir, err)
	}

	// Write token to file
	if err := os.WriteFile(c.KeaSecretPath, []byte(token), 0600); err != nil {
		return c.fallbackOrFail(token, "kea secret file "+c.KeaSecretPath, err)
	}

	return nil
}

// keaInstalled reports whether the kea-dhcp4 binary is present - the signal that
// this is a real appliance, not a dev sandbox. A package var so tests can force
// either mode. ponytail: the PATH+sbin list is duplicated from kea.keaBinaryPath /
// network.ToolPresent, but config is a foundational package that must not import
// those (import cycle + coupling); a local 8-line check is the lesser evil.
var keaInstalled = func() bool {
	if _, err := exec.LookPath("kea-dhcp4"); err == nil {
		return true
	}
	for _, p := range []string{"/usr/sbin/kea-dhcp4", "/usr/local/sbin/kea-dhcp4", "/sbin/kea-dhcp4"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// fallbackOrFail decides what a non-writable Kea secret/conf path means. In a dev
// sandbox (no kea-dhcp4 installed) it silently redirects to ./test-kea-gui so the
// app still runs. On a real appliance (kea-dhcp4 present) a non-writable /etc/kea
// is a genuine fault: silently repointing KeaConfDir would send every rendered
// kea-dhcp4.conf to a directory Kea never reads (reconciles "succeed", DHCP serves
// stale config forever), so it FAILS LOUD instead - Load()'s error aborts boot and
// systemd restarts, surfacing a transient race or a real permission problem.
func (c *Config) fallbackOrFail(token, what string, cause error) error {
	if keaInstalled() {
		return fmt.Errorf("%s is not writable and kea-dhcp4 is installed (not a dev sandbox) - refusing to silently redirect Kea config to ./test-kea-gui; fix permissions on %s: %w",
			what, filepath.Dir(c.KeaSecretPath), cause)
	}
	slog.Warn("kea secret path not writable and kea-dhcp4 absent - dev fallback to local paths (Kea configs will be written there too)",
		"what", what, "err", cause)
	return c.fallbackToLocalDir(token)
}

// fallbackToLocalDir repoints the Kea secret + conf paths at a writable local
// directory and writes the secret there. Only reached from fallbackOrFail when
// kea-dhcp4 is absent (a dev sandbox), never on a real appliance.
func (c *Config) fallbackToLocalDir(token string) error {
	const localDir = "./test-kea-gui"
	c.KeaSecretPath = filepath.Join(localDir, "gui-secret")
	c.KeaConfDir = localDir
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("failed to create fallback directory %s: %w", localDir, err)
	}
	if err := os.WriteFile(c.KeaSecretPath, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write fallback secret file: %w", err)
	}
	return nil
}

// ParseMariaDSN splits a go-sql-driver DSN of the form
// "user:pass@tcp(host:port)/dbname" into the discrete fields Kea's
// hosts-database config needs. The returned host has any :port stripped (Kea's
// MySQL connector defaults to 3306). Missing fields come back empty.
func ParseMariaDSN(dsn string) (host, user, pass, name string) {
	// An empty/whitespace DSN means MariaDB is unconfigured - return all-empty rather
	// than let the driver fill in its 127.0.0.1:3306 defaults (which would put a bogus
	// host into the Kea config for a box that has no host store).
	if strings.TrimSpace(dsn) == "" {
		return "", "", "", ""
	}
	// Prefer the driver's own parser: the hand-split below mis-reads a password that
	// contains '@' or '/', which would feed Kea the wrong credentials and silently kill
	// host reservations. ParseDSN is strict, so a partial/non-standard DSN (empty, no
	// '/', no '@') still falls through to the lenient hand-parse that preserves prior
	// behavior.
	if cfg, err := mysql.ParseDSN(dsn); err == nil {
		host = cfg.Addr
		if colon := strings.LastIndex(host, ":"); colon != -1 { // strip the :port
			host = host[:colon]
		}
		return host, cfg.User, cfg.Passwd, cfg.DBName
	}

	rest := dsn

	// dbname is everything after the last '/'
	if slash := strings.LastIndex(rest, "/"); slash != -1 {
		name = rest[slash+1:]
		rest = rest[:slash]
	}

	// credentials are everything before the first '@'
	if at := strings.Index(rest, "@"); at != -1 {
		creds := rest[:at]
		rest = rest[at+1:]
		if colon := strings.Index(creds, ":"); colon != -1 {
			user = creds[:colon]
			pass = creds[colon+1:]
		} else {
			user = creds
		}
	}

	// rest now looks like "tcp(host:port)" or "host:port"
	if openIdx := strings.Index(rest, "("); openIdx != -1 {
		if closeIdx := strings.Index(rest, ")"); closeIdx > openIdx {
			rest = rest[openIdx+1 : closeIdx]
		}
	}
	if hostColon := strings.Index(rest, ":"); hostColon != -1 {
		host = rest[:hostColon]
	} else {
		host = rest
	}

	return host, user, pass, name
}

// RedactedMariaDSN returns a password-free summary of the MariaDB DSN
// ("user@host/dbname") safe to write to logs.
func RedactedMariaDSN(dsn string) string {
	host, user, _, name := ParseMariaDSN(dsn)
	if user == "" {
		user = "?"
	}
	if host == "" {
		host = "?"
	}
	return fmt.Sprintf("%s@%s/%s", user, host, name)
}

// GetKeaSecret reads the generated randomized basic auth secret from disk.
func (c *Config) GetKeaSecret() (string, error) {
	data, err := os.ReadFile(c.KeaSecretPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
