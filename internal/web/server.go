package web

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ggo-kea-dhcp/internal/arpscan"
	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/ggoscan"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/netmon"
	"ggo-kea-dhcp/internal/network"
	"ggo-kea-dhcp/internal/preflight"
	"ggo-kea-dhcp/internal/version"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/a-h/templ"
	"github.com/starfederation/datastar-go/datastar"
)

type Server struct {
	cfg     *config.Config
	sqlite  *db.SQLiteDB
	mariadb *db.MariaDB
	kea     *kea.Client
	dns     *network.DNSManager
	net     *network.Manager
	// live is the in-process SSE broadcaster pushing state changes to connected
	// operators (lifecycle badge, tiles, lease/learnable lists) without polling.
	live *liveHub
	// netmon is the passive network-health monitor. It runs only while ACTIVE
	// (started/stopped by the reconciler), is a read-only observer that never
	// touches Kea, and feeds the dashboard's Network Health card + edge-triggered
	// audit rows. Best-effort: its Start never aborts the reconcile.
	netmon *netmon.MonitorManager
	// arp is the active device-presence prober: it ARPs each active lease IP and
	// reports which answered recently - the single source for the online/offline dot
	// on the leases/dashboard views. Runs only while ACTIVE, started/stopped beside
	// netmon. (netmon stays passive; this is the active counterpart that reliably
	// reaches quiet devices a passive capture never sees.)
	arp *arpscan.Prober
	// ggoscan is the active Green-GO device scanner (6464 device-scan): a firmware/model
	// inventory used for the firmware-mismatch warning and friendly hostnames. Runs only
	// while ACTIVE and only under a Green-GO preset, started/stopped beside netmon.
	ggoscan *ggoscan.Scanner
	// leaseIPs is a single TTL-memoized provider of the active-lease IPs, shared by the
	// ARP prober and the Green-GO scanner so their ~10s cycles collapse to ONE Kea
	// GetLeases round-trip per cycle instead of one each.
	leaseIPs func() []string
	// trunkProbe passively sniffs eth0 during onboarding to tell the setup wizard whether
	// the switch port is trunking tagged VLANs (the full monitor runs only in ACTIVE).
	// Started/stopped by the reconciler beside the onboarding bring-up.
	trunkProbe *netmon.TrunkProbe
	// metrics holds the dashboard's live trend series (lease count, pool
	// utilization, Kea RTT, uplink), filled by an always-on sampler independent of
	// the client-gated live ticker so a cold-opened dashboard has sparkline history.
	metrics *metricsStore
	// sysHealth is the appliance's live CPU/memory/storage gauge, sampled by the
	// same always-on sampler as metrics and surfaced as the header's system-health
	// indicator (ACTIVE only). cgo-free /proc + statfs reads; nil-safe.
	sysHealth *sysHealthStore
	// lastSeen tracks when each identity (normalized MAC for leases, flex-id key for
	// switch ports) was last observed active, so a pinned-but-offline port / offline
	// reservation can show "last active 3d ago". It is the freshest in-memory view
	// (updated every metrics sample from lease cltt); lastSeenWritten mirrors what has
	// been persisted to SQLite so the sampler only writes on a meaningful advance
	// (the Pi's SD card is write-sensitive). Both are primed from SQLite at startup.
	lastSeenMu      sync.RWMutex
	lastSeen        map[string]int64
	lastSeenWritten map[string]int64
	// applying guards against concurrent profile applies (a double-submit would
	// otherwise race two reconciles against the live Kea conf).
	applying atomic.Bool
	// loginThrottle slows brute-force sign-in attempts with a per-source-IP
	// escalating backoff (throttle-only, never a hard lockout).
	loginThrottle *loginThrottle
	// preflight holds the latest prerequisite-probe result for the diagnostics UI.
	// Set once at boot and refreshed by the live ticker so a fixed prerequisite
	// clears without a restart.
	preflightMu sync.RWMutex
	preflight   preflight.Result
	// health tracks live Kea/MariaDB reachability so the shell warns on every page
	// (Kea down = error, MariaDB down = warning) and transitions are audited.
	health *backendHealth
	// uplink debounces the WiFi-uplink audit so a persistently failing or repeatedly
	// re-applied uplink logs exactly one row per real up/down transition (zero value =
	// unknown, so the first connect attempt always audits its outcome).
	uplink uplinkAudit
}

// SetPreflight stores the latest preflight result.
func (s *Server) SetPreflight(r preflight.Result) {
	s.preflightMu.Lock()
	s.preflight = r
	s.preflightMu.Unlock()
}

// Preflight returns the latest preflight result.
func (s *Server) Preflight() preflight.Result {
	s.preflightMu.RLock()
	defer s.preflightMu.RUnlock()
	return s.preflight
}

func NewServer(cfg *config.Config, sqlite *db.SQLiteDB, mariadb *db.MariaDB) *Server {
	// Kea API user is hardcoded to "gui" matching kea-dhcp4.conf
	secret, _ := cfg.GetKeaSecret()
	keaClient := kea.NewClient(cfg.KeaAPIURL, "gui", secret)

	s := &Server{
		cfg:     cfg,
		sqlite:  sqlite,
		mariadb: mariadb,
		kea:     keaClient,
		dns:     network.NewDNSManager(),
		net:     network.NewManager(),
		live:    newLiveHub(),
	}
	// netmon emits one audit row per confirmed transition (never per tick) via
	// LogAudit, and reads its thresholds via GetState. The closures are the only
	// coupling - netmon imports neither web nor db. The audit Result is derived
	// from the event Severity so a rogue-DHCP (error) and a benign notice (warn)
	// read distinctly in the audit log rather than both as free-text "warning".
	s.netmon = netmon.NewMonitorManager(sqlite.GetState, func(e netmon.Event) {
		_ = s.sqlite.LogAudit("SYSTEM", e.Action, e.Target, e.Before, e.After, auditResult(e.Severity))
	})
	// The active ARP presence prober (started/stopped beside netmon by the reconciler).
	s.arp = arpscan.NewProber()
	// The active Green-GO device scanner (6464); started under a Green-GO preset, stopped
	// beside netmon/arp on every ACTIVE exit.
	s.ggoscan = ggoscan.NewScanner()
	// One memoized active-lease-IP provider shared by the ARP prober and the Green-GO
	// scanner (both probe the same lease set on a ~10s cycle).
	s.leaseIPs = memoizeLeaseIPs(func() ([]string, bool) {
		leases, err := s.kea.GetLeases(1000)
		if err != nil {
			return nil, false
		}
		out := make([]string, 0, len(leases))
		for _, l := range activeLeases(leases) {
			out = append(out, l.IPAddress)
		}
		return out, true
	}, leaseCacheTTL, time.Now)
	// The onboarding trunk probe (started in reconcileOnboarding, stopped on entering ACTIVE).
	s.trunkProbe = netmon.NewTrunkProbe()
	s.metrics = newMetricsStore()
	s.sysHealth = newSysHealthStore(cfg.DBPath)
	s.loginThrottle = newLoginThrottle()
	s.health = newBackendHealth()
	// Prime the last-seen maps from SQLite so a restart doesn't lose history or
	// re-write every row on the first sample.
	s.lastSeen = map[string]int64{}
	s.lastSeenWritten = map[string]int64{}
	if ls, err := sqlite.LoadLastSeen(); err == nil {
		for k, v := range ls {
			s.lastSeen[k] = v
			s.lastSeenWritten[k] = v
		}
	} else {
		log.Printf("[last-seen] prime from SQLite failed: %v", err)
	}
	return s
}

// lastSeenSnapshot returns a copy of the freshest last-seen map (identity -> epoch)
// for the page builders, so a render never holds the lock or races the sampler.
func (s *Server) lastSeenSnapshot() map[string]int64 {
	s.lastSeenMu.RLock()
	defer s.lastSeenMu.RUnlock()
	m := make(map[string]int64, len(s.lastSeen))
	for k, v := range s.lastSeen {
		m[k] = v
	}
	return m
}

// auditResult maps a netmon severity to the audit_log Result string.
func auditResult(sev netmon.Severity) string {
	switch sev {
	case netmon.SevError:
		return "ERROR"
	case netmon.SevWarn:
		return "WARNING"
	case netmon.SevInfo:
		return "INFO"
	default:
		return "OK"
	}
}

// Start runs the HTTP server and blocks until exit.
func (s *Server) Start() error {
	// One-shot: lift any legacy per-scope WiFi uplink up to the box-level keys before
	// the boot reconcile reads them.
	s.migrateUplinkToBoxLevel()

	// Bring runtime state in line with the persisted lifecycle state on boot.
	// Run it in the background so the web UI binds immediately - network/SoftAP
	// bring-up is slow, and an ACTIVE box must re-establish NM links, nft
	// masquerade, and ip_forward (not just Kea) which the old boot path skipped.
	go func() {
		if err := s.ReconcileApplianceState(ModeConverge, 0); err != nil {
			log.Printf("Boot reconcile (best-effort) reported: %v", err)
		}
		// Re-probe prerequisites now that the reconcile has brought Kea up (and
		// waited for its control socket): the synchronous boot-time preflight in
		// main.go races Kea's :8004 listener and records a false "Kea control
		// socket" warning. Refresh the frozen snapshot and push the always-on
		// banner so the stale warning self-clears without a Diagnostics visit.
		s.SetPreflight(preflight.Run(s.cfg))
		s.publishBackendAlert()
	}()

	// Keep the dashboard's Kea-derived live regions ticking while operators watch.
	s.startLiveTicker()

	// Sample the dashboard trend series on an always-on cadence (independent of the
	// client-gated ticker) so sparklines have history the moment a dashboard opens.
	s.startMetricsSampler()

	// Probe MariaDB reachability so a runtime outage (and its recovery) surfaces in
	// the UI and audit log. Kea health rides the metrics sampler.
	s.startBackendHealthProbe()

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
	mux.HandleFunc("GET /audit", s.handleAudit)
	mux.HandleFunc("GET /diagnostics", s.handleDiagnostics)
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("POST /settings/save", s.handleSettingsSave)
	mux.HandleFunc("GET /settings/backup", s.handleBackupExport)
	mux.HandleFunc("POST /settings/restore", s.handleSettingsRestore)
	mux.HandleFunc("POST /factory/restore", s.handleFactoryRestore)
	mux.HandleFunc("GET /reset", s.handleReset)
	mux.HandleFunc("POST /reset/routine", s.handleResetRoutine)
	mux.HandleFunc("POST /reset/factory", s.handleResetFactory)

	mux.HandleFunc("POST /system/reboot", s.handleSystemReboot)
	mux.HandleFunc("POST /system/poweroff", s.handleSystemPowerOff)

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
		return nil
	}
}

// isDatastar reports whether the request originates from the Datastar runtime
// (a backend-action fetch expecting an SSE response), the new-stack analogue of
// isHTMX. Datastar sets this header on every @get/@post/@delete action.
func isDatastar(r *http.Request) bool {
	return r.Header.Get("Datastar-Request") == "true"
}

// renderTempl renders a templ component as a full HTML response.
func (s *Server) renderTempl(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.Render(r.Context(), w); err != nil {
		log.Printf("templ render error: %v", err)
	}
}

// pageData assembles the shell context (lifecycle state, auth + CSRF token,
// current path, one-shot flash) every full page needs. It consumes the flash
// cookie, so call it once per response.
func (s *Server) pageData(w http.ResponseWriter, r *http.Request, title string) views.PageData {
	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	d := views.PageData{State: state, CurrentPath: r.URL.Path, Title: title, AssetVer: assetVersion, Version: version.Number, HealthPill: views.StatusPillView{State: state}}
	if username, csrf, ok := s.sessionInfo(r); ok {
		d.Authenticated = true
		d.Username = username
		d.CSRFToken = csrf
		d.SysHealth = s.buildSysHealthView(state)
		d.HealthPill = s.buildStatusPill(state)
		if s.health != nil {
			d.BackendAlerts = s.backendAlertRows() // first paint of the #backend-alert strip (health + preflight)
		}
	}
	if f := s.getFlash(w, r); f != nil {
		d.Flash = &views.Flash{Message: f.Message, Type: f.Type}
	}
	return d
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

// Middleware & helper utilities

// redirect navigates the client to path: a Datastar SSE redirect for Datastar
// actions, else a plain 302 (native form posts and full page loads).
func (s *Server) redirectHTMX(w http.ResponseWriter, r *http.Request, path string) {
	if isDatastar(r) {
		sse := datastar.NewSSE(w, r)
		_ = sse.Redirect(path)
		return
	}
	http.Redirect(w, r, path, http.StatusFound)
}

type FlashMessage struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (s *Server) setFlash(w http.ResponseWriter, msg, msgType string) {
	flash := FlashMessage{
		Message: msg,
		Type:    msgType,
	}
	data, _ := json.Marshal(flash)
	http.SetCookie(w, &http.Cookie{
		Name:     "ggo_flash",
		Value:    hex.EncodeToString(data),
		Path:     "/",
		HttpOnly: false,
		MaxAge:   60,
	})
}

func (s *Server) getFlash(w http.ResponseWriter, r *http.Request) *FlashMessage {
	cookie, err := r.Cookie("ggo_flash")
	if err != nil {
		return nil
	}

	// Delete cookie immediately
	http.SetCookie(w, &http.Cookie{
		Name:     "ggo_flash",
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		MaxAge:   -1,
	})

	data, err := hex.DecodeString(cookie.Value)
	if err != nil {
		return nil
	}

	var flash FlashMessage
	if err := json.Unmarshal(data, &flash); err != nil {
		return nil
	}

	return &flash
}

func (s *Server) handleError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	log.Printf("Error: %s (status code: %d)", msg, code)
	if isDatastar(r) {
		// Append an error toast into the live toast region; the page stays put.
		sse := datastar.NewSSE(w, r)
		_ = sse.PatchElementTempl(views.Toast(msg, "error"),
			datastar.WithSelectorID("toast-container"), datastar.WithModeAppend())
		return
	}
	// A mutating native form post: show the message as an error flash on the page the
	// request came from (post-redirect-get) rather than a bare error page. This is what
	// makes a validation/conflict rejection on a native form (reservations, pinning,
	// settings) read as a toast instead of dumping the operator on a blank page. Falls
	// back to the dashboard when there is no usable same-site Referer.
	//
	// Only for unsafe methods: a GET handler (e.g. the backup download) keeps its real
	// status - redirecting a GET error would drop the status code and could loop if the
	// failing page is its own Referer.
	if isUnsafeMethod(r.Method) {
		back := refererPath(r)
		if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") {
			back = "/"
		}
		s.setFlash(w, msg, "error")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	http.Error(w, msg, code)
}

func (s *Server) getActor(r *http.Request) string {
	if username, _, ok := s.sessionInfo(r); ok {
		return username
	}
	return "admin"
}

// isUnsafeMethod reports whether the HTTP method mutates state (and thus needs
// CSRF validation).
func isUnsafeMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
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

func (s *Server) lifecycleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/static/") || path == "/api/state" {
			// /api/state is the public lifecycle-state probe the CONFIGURING page polls
			// to reload itself once the apply finishes (no auth, reachable in any state).
			next.ServeHTTP(w, r)
			return
		}

		state, _ := s.sqlite.GetState(db.LifecycleStateKey)
		if state == "" {
			state = db.StateFactory
		}

		// State: FACTORY - only the admin-bootstrap pages are reachable, and only
		// pre-auth (there is no admin yet). /wifi/scan is no longer exposed here.
		if state == db.StateFactory {
			if path != "/factory" && path != "/factory/setup" && path != "/factory/restore" {
				http.Redirect(w, r, "/factory", http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Authenticate via session cookie.
		var authenticated bool
		var csrfToken string
		if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
			if _, csrf, ok := s.sessionUser(cookie.Value); ok {
				authenticated = true
				csrfToken = csrf

				// Slide the 1h idle window forward, but at most ~once / 10 min (the 1h
				// TTL minus a 50-min floor) to avoid a DB write on every authenticated
				// request (the SSE live stream + Datastar actions). When it actually
				// slides, re-issue the cookie so the browser's 1h MaxAge tracks the
				// server window (the 12h absolute cap lives in created_at, enforced in
				// sessionUser). Past the cap, sessionUser already failed auth above.
				if res, err := s.sqlite.Exec("UPDATE sessions SET expires_at = datetime('now', '+1 hour') WHERE session_id = ? AND expires_at < datetime('now', '+50 minutes')", cookie.Value); err == nil {
					if n, _ := res.RowsAffected(); n > 0 {
						setSessionCookie(w, r, cookie.Value)
					}
				}
			}
		}

		if !authenticated {
			if path != "/login" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// CSRF: every state-changing request from an authenticated session must
		// carry the matching token (htmx sends it as a header; forms as a field).
		// SameSite=Strict on the cookie is the primary mitigation; this is the
		// defense-in-depth token check.
		if isUnsafeMethod(r.Method) {
			provided := r.Header.Get("X-CSRF-Token")
			if provided == "" {
				provided = r.FormValue("csrf_token")
			}
			if subtle.ConstantTimeCompare([]byte(provided), []byte(csrfToken)) != 1 {
				http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
				return
			}
		}

		// Authenticated users trying to access login or factory pages
		if path == "/login" || path == "/factory" {
			http.Redirect(w, r, s.postAuthRedirect(), http.StatusFound)
			return
		}

		// Per-state path authorization (ONBOARDING confines to setup/settings;
		// ACTIVE blocks the setup wizard).
		if redirect := stateRedirectFor(state, path); redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// stateRedirectFor returns where an authenticated request should be redirected
// when the current lifecycle state forbids the path, or "" when it may proceed.
// Pure, so the routing rules are unit-testable without spinning up a server.
func stateRedirectFor(state, path string) string {
	switch state {
	case db.StateOnboarding:
		switch path {
		case "/setup", "/setup/apply", "/setup/pools/edit", "/settings", "/settings/save", "/settings/backup", "/settings/restore", "/logout", "/wifi/scan", "/sse/live":
			// /sse/live is opened by the shell on every authenticated page (it keeps
			// the wizard's link-status badge live). Without it whitelisted here, the
			// middleware 302s the stream to /setup; Datastar follows the redirect,
			// receives the full /setup page (whose #scopes-container is empty), and
			// morphs it in - wiping the scope card the wizard JS just added.
			return ""
		default:
			return "/setup"
		}
	case db.StateConfiguring:
		// An apply is in flight: keep the operator on the dashboard (and stop a
		// second apply from starting). The reconnect interstitial's /dashboard
		// navigation lands on the dashboard instead of bouncing to /setup before
		// the apply goroutine flips the state to ACTIVE.
		if path == "/setup" || path == "/setup/apply" {
			return "/dashboard"
		}
	case db.StateActive:
		// ACTIVE allows the setup wizard as "create a new configuration" - that is
		// how a second profile (and thus profile switching) becomes reachable.
	}
	return ""
}
