package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// initKeaSecret ensures the Kea basic auth secret file exists and is populated with a random token.
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
		// Fallback to a local path if the system directory is not writable (e.g. read-only fs, permission denied)
		localDir := "./test-kea-gui"
		c.KeaSecretPath = filepath.Join(localDir, "gui-secret")
		c.KeaConfDir = localDir
		if err := os.MkdirAll(localDir, 0755); err != nil {
			return fmt.Errorf("failed to create fallback directory %s: %w", localDir, err)
		}
	}

	// Write token to file
	if err := os.WriteFile(c.KeaSecretPath, []byte(token), 0600); err != nil {
		// Fallback on write error
		localDir := "./test-kea-gui"
		c.KeaSecretPath = filepath.Join(localDir, "gui-secret")
		c.KeaConfDir = localDir
		_ = os.MkdirAll(localDir, 0755)
		if err := os.WriteFile(c.KeaSecretPath, []byte(token), 0600); err != nil {
			return fmt.Errorf("failed to write fallback secret file: %w", err)
		}
	}

	return nil
}

// ParseMariaDSN splits a go-sql-driver DSN of the form
// "user:pass@tcp(host:port)/dbname" into the discrete fields Kea's
// hosts-database config needs. The returned host has any :port stripped (Kea's
// MySQL connector defaults to 3306). Missing fields come back empty.
func ParseMariaDSN(dsn string) (host, user, pass, name string) {
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
