package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/preflight"
	"ggo-kea-dhcp/internal/version"
	"ggo-kea-dhcp/internal/web"
)

// setupLogging installs an slog text handler on stderr at the configured level.
// slog.SetDefault also routes the stdlib log package through this handler (at
// info), so existing log.Printf calls share formatting and level filtering. The
// time attribute is dropped because journald already stamps every line.
func setupLogging(level string) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lv,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
	log.SetFlags(0) // journald stamps; avoid a duplicate timestamp in the message
}

func main() {
	// 1. Load config (parses flags) then install logging at the chosen level.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	setupLogging(cfg.LogLevel)

	// --check: run the preflight prerequisite probes and exit with a status code the
	// installer's postinst can act on (0 = all good, 1 = a hard prerequisite failed).
	if cfg.Check {
		os.Exit(runCheck(cfg))
	}

	log.Printf("Starting Green-GO Kea DHCP Server (%s) v%s...", version.Name, version.Number)

	// Validate the Kea API secret is readable, but never log its value.
	if _, err := cfg.GetKeaSecret(); err != nil {
		log.Fatalf("Failed to read Kea API secret: %v", err)
	}

	log.Printf("Configuration loaded successfully.")
	log.Printf("  Bind address: %s", cfg.BindAddr)
	log.Printf("  SQLite database: %s", cfg.DBPath)
	log.Printf("  Kea config dir: %s", cfg.KeaConfDir)
	log.Printf("  Kea secret file: %s", cfg.KeaSecretPath)
	log.Printf("  MariaDB: %s", config.RedactedMariaDSN(cfg.MariaDBDSN))

	// 2. Initialize SQLite Control Plane
	sqlite, err := db.OpenSQLite(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open SQLite database: %v", err)
	}
	defer sqlite.Close()
	log.Println("SQLite Control Plane database initialized successfully.")

	// Query lifecycle state
	state, err := sqlite.GetState(db.LifecycleStateKey)
	if err != nil {
		log.Fatalf("Failed to read lifecycle state: %v", err)
	}
	log.Printf("Current appliance lifecycle state: %s", state)

	// Runtime bring-up for the current lifecycle state (onboarding SoftAP/eth0/
	// Kea, or active links/NAT/Kea) is owned by the reconciler, invoked from
	// Server.Start(). Boot no longer duplicates that logic here.

	// Log startup audit event
	err = sqlite.LogAudit("SYSTEM", "STARTUP", version.Name, "", "", "SUCCESS")
	if err != nil {
		log.Printf("Warning: failed to write audit log: %v", err)
	}

	// 3. Initialize MariaDB Data Plane (warn if failing, do not crash, as DB might start later or we are onboarding)
	var mariadb *db.MariaDB
	mariadb, err = db.ConnectMariaDB(cfg.MariaDBDSN)
	if err == nil {
		if err := mariadb.VerifySchema(); err != nil {
			log.Printf("Warning: MariaDB connection succeeded but schema verification failed: %v", err)
		} else {
			log.Println("MariaDB Data Plane connected and verified successfully.")
		}
	} else {
		log.Printf("Warning: failed to connect to MariaDB: %v", err)
	}

	// 4. Start HTTP Web UI Dashboard Server
	server := web.NewServer(cfg, sqlite, mariadb)

	// Probe prerequisites: stash for the diagnostics UI, log problems, and audit
	// non-OK results. Never aborts boot - the operator sees issues in the UI.
	pf := preflight.Run(cfg)
	server.SetPreflight(pf)
	logPreflight(pf, sqlite)

	if err := server.Start(); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

// runCheck runs the preflight probes, prints a table to stdout, and returns the
// process exit code (0 = all good, 1 = a hard prerequisite failed).
func runCheck(cfg *config.Config) int {
	res := preflight.Run(cfg)
	for _, c := range res {
		fmt.Printf("[%-4s] %s - %s\n", c.Status, c.Name, c.Detail)
	}
	if res.HasFailure() {
		fmt.Println("\nPreflight FAILED: one or more hard prerequisites are missing.")
		return 1
	}
	fmt.Println("\nPreflight OK.")
	return 0
}

// logPreflight logs non-OK checks and records them in the audit log, so the boot
// state is visible both in journald and in the in-app audit trail.
func logPreflight(res preflight.Result, sqlite *db.SQLiteDB) {
	for _, c := range res {
		switch c.Status {
		case preflight.Fail:
			slog.Error("preflight", "check", c.Name, "detail", c.Detail)
		case preflight.Warn:
			slog.Warn("preflight", "check", c.Name, "detail", c.Detail)
		default:
			slog.Info("preflight", "check", c.Name, "detail", c.Detail)
		}
		if c.Status != preflight.OK {
			_ = sqlite.LogAudit("SYSTEM", "PREFLIGHT", c.Name, "", c.Detail, string(c.Status))
		}
	}
	if res.HasFailure() {
		slog.Error("preflight found missing hard prerequisites - the appliance started but core DHCP may not work; see the diagnostics view")
	}
}
