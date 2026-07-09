package web

import (
	"context"
	"io"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/preflight"
)

// Start runs the HTTP server and blocks until exit.
func (s *Server) Start() error {
	// One-shot: lift any legacy per-scope WiFi uplink up to the box-level keys before
	// the boot reconcile reads them.
	s.migrateUplinkToBoxLevel()

	// Fold any pending self-update outcome into the audit log (UPDATE_APPLIED /
	// UPDATE_FAILED / needs_system) and clear stale staging leftovers.
	s.reconcileUpdateResult()

	// Bring runtime state in line with the persisted lifecycle state on boot.
	// Run it in the background so the web UI binds immediately - network/SoftAP
	// bring-up is slow, and an ACTIVE box must re-establish NM links, nft
	// masquerade, and ip_forward (not just Kea) which the old boot path skipped.
	go s.runRecoveredAudited("boot-reconcile", func() {
		// Hold the mutation guard for the boot reconcile, like every other reconcile
		// path, so a fast operator apply/switch arriving the instant the listener binds
		// cannot run a second reconcile concurrently over the same NM connections and
		// kea-dhcp4.conf. Synchronous begin/end (this is already its own goroutine, so
		// no scheduleReconcileHeld). The guard being busy at boot is near-impossible
		// (nothing else claims it before the listener is up); if it happens, the
		// winning request's own reconcile converges state, so skipping is safe.
		if s.beginReconcile() {
			// Deferred, not sequential: the recover wrapper above absorbs a panic,
			// and an absorbed panic must not leave the mutation guard held forever.
			func() {
				defer s.endReconcile()
				if err := s.ReconcileApplianceState(ModeConverge, 0); err != nil {
					// Audit, not just stderr: a box that boots "ACTIVE" but couldn't raise an
					// interface would otherwise look healthy everywhere but journalctl. The
					// Diagnostics page lists recent SYSTEM events, so this reaches the UI.
					log.Printf("Boot reconcile (best-effort) reported: %v", err)
					_ = s.sqlite.LogAudit("SYSTEM", "RECONCILE_FAILED", "boot", "", err.Error(), "WARNING")
				}
			}()
		} else {
			log.Printf("Boot reconcile skipped: an apply is already in progress")
		}
		// Re-probe prerequisites now that the reconcile has brought Kea up (and
		// waited for its control socket): the synchronous boot-time preflight in
		// main.go races Kea's :8004 listener and records a false "Kea control
		// socket" warning. Refresh the frozen snapshot and push the always-on
		// banner so the stale warning self-clears without a Diagnostics visit.
		s.SetPreflight(preflight.Run(s.cfg))
		s.publishBackendAlert()
	})

	// Keep the dashboard's Kea-derived live regions ticking while operators watch.
	s.startLiveTicker()

	// Sample the dashboard trend series on an always-on cadence (independent of the
	// client-gated ticker) so sparklines have history the moment a dashboard opens.
	s.startMetricsSampler()

	// Record system-clock steps and the first NTP sync to the audit log, so a
	// lease-table wipe caused by an RTC-less box jumping its clock forward is
	// diagnosable after the fact rather than a silent mystery.
	s.startClockWatch()

	// Probe MariaDB reachability so a runtime outage (and its recovery) surfaces in
	// the UI and audit log. Kea health rides the metrics sampler.
	s.startBackendHealthProbe()

	// Release checks: every 30 min while ACTIVE (each successful uplink connect
	// also kicks one). Notify-only - installing is always a deliberate operator action.
	s.startUpdateCheckLoop()

	mux := http.NewServeMux()

	// Static assets: the offline-first Datastar runtime, self-hosted fonts, and
	// the Console style.css, all embedded under static/ and served by handleStatic.
	mux.HandleFunc("GET /static/{file...}", s.handleStatic)

	// Live state channel (SSE). One long-lived connection per operator.
	mux.HandleFunc("GET /sse/live", s.handleSSELive)

	// Public lifecycle-state probe: the CONFIGURING page polls this and reloads itself
	// once the apply lands ACTIVE, so the header pill never depends on the live SSE
	// surviving the eth0 bounce an apply does.
	mux.HandleFunc("GET /api/state", s.handleAPIState)

	// App Routes
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)
	// The signed-in admin's own credentials (header account dialog). Deliberately
	// NOT in the ONBOARDING whitelist - account changes are a settled-appliance
	// action, not part of bring-up.
	mux.HandleFunc("POST /account/save", s.handleAccountSave)
	mux.HandleFunc("GET /factory", s.handleFactory)
	mux.HandleFunc("POST /factory/setup", s.handleFactorySetup)
	mux.HandleFunc("GET /setup", s.handleSetup)

	mux.HandleFunc("POST /setup/pools/edit", s.handleWizardPoolEdit)
	mux.HandleFunc("POST /setup/apply", s.handleSetupApply)
	mux.HandleFunc("GET /wifi/scan", s.handleWifiScan)
	mux.HandleFunc("GET /dashboard", s.handleDashboard)
	mux.HandleFunc("POST /profile/activate", s.handleProfileActivate)
	mux.HandleFunc("POST /profile/delete", s.handleProfileDelete)
	mux.HandleFunc("GET /pools", s.handlePools)
	mux.HandleFunc("POST /pools/edit", s.handlePoolsPlanOp)
	mux.HandleFunc("POST /pools/save", s.handlePoolsPlanSave)
	mux.HandleFunc("GET /leases", s.handleLeases)
	mux.HandleFunc("POST /reservations/import", s.handleReservationImport)
	mux.HandleFunc("GET /leases/search", s.handleLeasesSearch)
	mux.HandleFunc("DELETE /leases/release", s.handleLeaseRelease)
	mux.HandleFunc("POST /reservations/add", s.handleReservationAdd)
	mux.HandleFunc("POST /reservations/delete", s.handleReservationDelete)
	mux.HandleFunc("GET /pinning", s.handlePinning)
	mux.HandleFunc("POST /pinning/pin", s.handlePin)
	mux.HandleFunc("POST /pinning/unpin", s.handleUnpin)
	mux.HandleFunc("POST /pinning/label", s.handleLabel)
	mux.HandleFunc("POST /device/reboot", s.handleDeviceReboot)
	mux.HandleFunc("GET /audit", s.handleAudit)
	mux.HandleFunc("GET /diagnostics", s.handleDiagnostics)
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("POST /settings/save", s.handleSettingsSave)
	mux.HandleFunc("POST /settings/backup", s.handleBackupExport)
	mux.HandleFunc("POST /settings/restore", s.handleSettingsRestore)
	mux.HandleFunc("POST /factory/restore", s.handleFactoryRestore)
	mux.HandleFunc("GET /reset", s.handleReset)
	mux.HandleFunc("POST /reset/routine", s.handleResetRoutine)
	mux.HandleFunc("POST /reset/factory", s.handleResetFactory)

	mux.HandleFunc("POST /rogue/standdown", s.handleStandDown)
	mux.HandleFunc("POST /rogue/resume", s.handleResumeDHCP)

	mux.HandleFunc("POST /system/reboot", s.handleSystemReboot)
	mux.HandleFunc("POST /system/poweroff", s.handleSystemPowerOff)

	mux.HandleFunc("POST /update/check", s.handleUpdateCheck)
	mux.HandleFunc("POST /update/install", s.handleUpdateInstall)

	// The dedicated CaptiveRedirectMiddleware was dropped: lifecycleMiddleware is
	// the outer wrapper and already 302s unauthenticated onboarding probes to
	// /login, which is what triggers the OS captive-portal assistant. A separate
	// inner middleware never ran.
	log.Printf("Starting dashboard server on %s", s.cfg.BindAddr)
	srv := &http.Server{
		Addr:    s.cfg.BindAddr,
		Handler: s.lifecycleMiddleware(mux),
		// Slowloris guard. No WriteTimeout: the SSE live channel is long-lived and
		// a write deadline would kill it.
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown: under systemd, SIGTERM otherwise kills the process before
	// main's defers (notably sqlite.Close) run. Return from Start on signal so those
	// defers execute.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		return err // failed to bind, or the listener crashed
	case <-ctx.Done():
		log.Printf("Shutdown signal received; draining...")
		// Bounded drain. Long-lived SSE clients never go idle, so Shutdown will hit
		// this deadline - expected, we're exiting anyway. Don't surface it as a fatal.
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		s.stopBackground()
		return nil
	}
}

// stopBackground halts every background service and ticker loop before Start
// returns, so main's deferred sqlite.Close never races goroutines still issuing
// queries. bg.stop ends and joins the loops (see bgRunner); the service Stops
// below are idempotent, matching the reconciler's own teardown paths.
func (s *Server) stopBackground() {
	s.bg.stop()
	// Both teardowns are the same ones the reconciler's lifecycle paths use, so a
	// monitor added to either set is torn down on shutdown too (rather than
	// stranded in a copy here).
	s.stopActiveMonitors()
	s.mon.stopOnboarding()
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	switch state {
	case db.StateFactory:
		http.Redirect(w, r, "/factory", http.StatusFound)
	case db.StateActive, db.StateConfiguring:
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	default:
		http.Redirect(w, r, "/setup", http.StatusFound)
	}
}

// handleAPIState returns the current lifecycle state as plain text. Public and
// cache-busted: the CONFIGURING page polls it to reload once the apply reaches ACTIVE.
//
// Intentionally unauthenticated (whitelisted ahead of the auth check in
// lifecycleMiddleware): it must answer across the eth0 re-IP an apply performs, when
// the session/SSE can't survive. The only thing it discloses is the lifecycle-state
// string (FACTORY/ONBOARDING/CONFIGURING/ACTIVE) - no config, leases, or secrets -
// and the box sits behind Caddy on the operator LAN, so the exposure is acceptable.
func (s *Server) handleAPIState(w http.ResponseWriter, r *http.Request) {
	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	if state == "" {
		state = db.StateFactory
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, state)
}
