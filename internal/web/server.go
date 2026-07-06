package web

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ggo-kea-dhcp/internal/arpscan"
	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/dns"
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

// deviceScanner is the subset of *ggoscan.Scanner the web layer drives. Declaring the
// field as an interface lets a test inject a fake inventory and capture the reboot send
// without opening a real socket. *ggoscan.Scanner satisfies it.
type deviceScanner interface {
	Start([]ggoscan.Spec)
	Stop()
	Snapshot() ggoscan.Snapshot
	SendReboot(ip string) error
}

// presenceProber is the subset of *arpscan.Prober the web layer drives, seamed for the
// same reason: a test can report presence and the live MAC at an IP. *arpscan.Prober
// satisfies it.
type presenceProber interface {
	Start([]arpscan.Spec)
	Stop()
	Snapshot() arpscan.Snapshot
	ProbeHost(ip string) (mac string, alive bool)
}

type Server struct {
	cfg     *config.Config
	sqlite  *db.SQLiteDB
	mariadb *db.MariaDB
	kea     *kea.Client
	// dns is the single owner of UDP port 53: stopped through FACTORY/ONBOARDING
	// (the reconciler deliberately serves no DNS there), authoritative for the
	// device zones + dumb forwarder in ACTIVE. The zone is rebuilt from leases,
	// reservations and scan names on the dashboard cadence (rebuildDNSZone).
	dns *dns.Server
	net *network.Manager
	// dnsZoneSig gates the metrics sampler's zone rebuild so an idle box does not
	// re-query reservations every 12s (event-driven rebuilds ride publishDashboard).
	dnsZoneSig atomic.Uint64
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
	arp presenceProber
	// ggoscan is the active Green-GO device scanner (6464 device-scan): a firmware/model
	// inventory used for the firmware-mismatch warning and friendly hostnames. Runs only
	// while ACTIVE and only under a Green-GO preset, started/stopped beside netmon.
	ggoscan deviceScanner
	// ggoFwMu guards ggoFwScopes: the greengo-preset scopes the scanner targets
	// (iface + subnet), refreshed on every startGgoScan. Used to attribute
	// firmware-mismatch findings to the owning scope's Network Health sub-card.
	// Never cleared on Stop - outside ACTIVE netmon is down too, so there are no
	// interface cards to attach to and a stale mapping is inert.
	ggoFwMu     sync.Mutex
	ggoFwScopes []fwScope
	// ggoFwLastSig is the last audited firmware-mismatch census ("" = uniform), so
	// attachFirmware audits transitions once, not on every render (see
	// auditFirmwareTransition).
	ggoFwLastSig string
	// leaseIPs is a single TTL-memoized provider of the active-lease IPs, shared by the
	// ARP prober and the Green-GO scanner so their ~10s cycles collapse to ONE Kea
	// GetLeases round-trip per cycle instead of one each.
	leaseIPs func() []string
	// leaseSrc is the shared short-TTL lease provider every background cadence
	// and display path reads through (see leasecache.go) - the single Kea
	// lease fetcher outside the mutation handlers, which stay direct because
	// they act on the state they read.
	leaseSrc *leaseCache
	// trunkProbe passively sniffs eth0 during onboarding to tell the setup wizard whether
	// the switch port is trunking tagged VLANs (the full monitor runs only in ACTIVE).
	// Started/stopped by the reconciler beside the onboarding bring-up.
	trunkProbe *netmon.TrunkProbe
	// rogueProbe passively watches eth0 during onboarding for a foreign DHCP server
	// already answering (an OFFER/ACK carrying another server-id), feeding the wizard's
	// shield badge. Same lifecycle as trunkProbe. Interface-typed so wizard tests can
	// fake a detection without a capture socket.
	rogueProbe rogueProber
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
	// lastLeases caches the most recent successful Kea lease fetch so the degraded
	// (Kea-down) live path can keep rendering the periodic regions from known data
	// instead of freezing every region for the whole outage.
	lastLeasesMu sync.Mutex
	lastLeases   []kea.ActiveLease
	// applying guards against concurrent profile applies (a double-submit would
	// otherwise race two reconciles against the live Kea conf).
	applying atomic.Bool
	// rescueArmed opens the zero-scopes rescue window: armed at process start,
	// consumed by the FIRST ACTIVE converge (usually boot). Only inside that
	// window may a nothing-to-serve ACTIVE box demote itself to ONBOARDING - a
	// later converge (a mid-show settings save) must surface the error instead,
	// never tear a serving box down to the SoftAP.
	rescueArmed atomic.Bool
	// updating guards the self-update install path: claimed by POST /update/install
	// (alongside the applying guard) and held until the updater reports a result or
	// the control plane restarts onto the new binary.
	updating atomic.Bool
	// updateHTTP is the dedicated outbound client for GitHub release checks and the
	// .deb download - separate from the Kea client so a wedged remote can never
	// contend with control-socket traffic. updateAPIBase is the API origin
	// (overridden by tests to an httptest server); updateDir is the .deb staging
	// directory (the StateDirectory's update/ subdir in production).
	updateHTTP    *http.Client
	updateAPIBase string
	updateRepo    string
	updateDir     string
	// loginThrottle slows brute-force sign-in attempts with a per-source-IP
	// escalating backoff (throttle-only, never a hard lockout).
	loginThrottle *loginThrottle
	// done is closed on shutdown to end the background loops (live ticker,
	// metrics sampler, MariaDB probe, update check + kicked checks + result
	// watcher, clock watch) before main's deferred sqlite.Close runs - otherwise
	// they keep querying a closing database on every service restart and
	// self-update. bgWG counts those goroutines so stopBackground can JOIN them:
	// signalling alone leaves a loop already past its select free to issue
	// multi-statement work into the closing database.
	done chan struct{}
	bgWG sync.WaitGroup
	// bgMu + bgStopping order bgWG.Add against stopBackground's Wait: a
	// registration racing shutdown (kickUpdateCheck fires from reconcile
	// goroutines the join does not cover) must either land before the Wait or
	// be refused - Add concurrent with a zero-counter Wait is the documented
	// WaitGroup misuse. bgStopping also makes stopBackground idempotent.
	bgMu       sync.Mutex
	bgStopping bool
	// lastMaint is when the storage-maintenance pass (snapshot/audit/session
	// pruning) last ran. Touched only by the metrics sampler goroutine.
	lastMaint time.Time
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
	// hwResFetch overrides the hw-address reservation fetch in tests (a counting fake),
	// so the per-broadcast fetch-count invariant is assertable. nil in production, where
	// fetchHWReservationMap reads MariaDB directly.
	hwResFetch func(context.Context) map[string]db.HostReservation
}

// rogueProber is the onboarding rogue-DHCP probe surface (*netmon.RogueProbe in
// production; faked in wizard tests).
type rogueProber interface {
	Start(iface string)
	Stop()
	// Watching is false when the probe is stopped or blind (no CAP_NET_RAW), so
	// the shield can report "unverified" instead of a false all-clear.
	Watching() bool
	Server() (ip, mac string, ok bool)
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
		dns:     dns.New(""),
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
	// The shared lease provider (leasecache.go); every read-through consumer
	// below funnels into this one fetcher.
	s.leaseSrc = newLeaseCache(func(ctx context.Context) ([]kea.ActiveLease, error) {
		return s.kea.GetLeases(ctx, 1000)
	})
	// One memoized active-lease-IP provider shared by the ARP prober and the Green-GO
	// scanner (both probe the same lease set on a ~10s cycle); its fetch reads
	// through leaseSrc so the cycle shares the ticker/sampler round-trip.
	s.leaseIPs = memoizeLeaseIPs(func() ([]string, bool) {
		ctx, cancel := opCtx()
		defer cancel()
		leases, err := s.getLeases(ctx, leaseSrcTTL)
		if err != nil {
			return nil, false
		}
		out := make([]string, 0, len(leases))
		for _, l := range activeLeases(leases) {
			out = append(out, l.IPAddress)
		}
		return out, true
	}, leaseCacheTTL, time.Now)
	// The onboarding trunk + rogue-DHCP probes (started in reconcileOnboarding,
	// stopped on entering ACTIVE).
	s.trunkProbe = netmon.NewTrunkProbe()
	s.rogueProbe = netmon.NewRogueProbe()
	s.metrics = newMetricsStore()
	s.sysHealth = newSysHealthStore(cfg.DBPath)
	s.updateHTTP = newUpdateHTTPClient()
	// The update origin and repo default to the canonical GitHub release feed but
	// can be pointed elsewhere (a scratch repo, a local mock) via the environment,
	// injected by the unit's optional update.env EnvironmentFile. Both must move
	// together: the app stages from this repo, and the root updater independently
	// re-verifies the digest against the SAME repo (see updater.sh) - overriding
	// only one would fail the digest gate closed. Empty env = production defaults.
	s.updateAPIBase = envOr("GGO_UPDATE_API", defaultUpdateAPIBase)
	s.updateRepo = envOr("GGO_UPDATE_REPO", updateRepo)
	s.updateDir = filepath.Join(filepath.Dir(cfg.DBPath), "update")
	s.loginThrottle = newLoginThrottle()
	s.rescueArmed.Store(true)
	s.health = newBackendHealth()
	s.done = make(chan struct{})
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
	return maps.Clone(s.lastSeen)
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

// envOr returns the environment variable value when set and non-empty, else def.
// Used for the optional update-origin overrides injected via the unit's
// update.env EnvironmentFile.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// runRecovered runs fn, logging and absorbing a panic. Background goroutines
// (ticks, probes, the boot reconcile) don't get the net/http per-connection
// recovery, so without this a panic in any of them kills the whole process -
// DHCP management, DNS, and the UI together. A skipped cycle is the correct
// degradation; the next tick retries.
func runRecovered(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] recovered from panic: %v", name, r)
		}
	}()
	fn()
}

// runRecoveredAudited is runRecovered for the detached reconcile goroutines
// (finish-apply/switch, held reconciles, uplink connect, zone prime). A panic
// there strands the box mid-transition, so besides absorbing it the recovery is
// audited - Diagnostics is often the only place an operator can see why an
// apply never finished. fn's own defers (endReconcile) run during unwinding,
// before the recover here, so the mutation guard is always released.
func (s *Server) runRecoveredAudited(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] recovered from panic: %v", name, r)
			_ = s.sqlite.LogAudit("SYSTEM", "PANIC_RECOVERED", name, "", fmt.Sprint(r), "ERROR")
		}
	}()
	fn()
}

// runRecoveredReconcile is runRecoveredAudited for the goroutines that own a
// lifecycle transition (finish-apply, finish-switch). A crash there used to be
// self-healing - systemd restarted the process and the boot reconcile completed
// or reverted the interrupted apply within seconds. Absorbing the panic removes
// that restart, so recovery kicks ONE background converge instead: the box is
// likely stranded in persisted CONFIGURING with monitors and DNS already torn
// down, and the converge dispatches straight into resumeInterruptedApply. The
// kicked converge runs under the plain recover wrapper - a second panic there
// is absorbed without kicking again, so this cannot loop.
func (s *Server) runRecoveredReconcile(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] recovered from panic: %v", name, r)
			_ = s.sqlite.LogAudit("SYSTEM", "PANIC_RECOVERED", name, "", fmt.Sprint(r), "ERROR")
			go runRecovered(name+"-recovery", func() {
				if !s.beginReconcile() {
					return // another reconcile is running; it converges the state
				}
				defer s.endReconcile()
				if err := s.ReconcileApplianceState(ModeConverge, 0); err != nil {
					log.Printf("[%s-recovery] converge after panic: %v", name, err)
					_ = s.sqlite.LogAudit("SYSTEM", "RECONCILE_FAILED", name+"-recovery", "", err.Error(), "WARNING")
				}
			})
		}
	}()
	fn()
}

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

// addBackground registers one goroutine with the shutdown join, refusing once
// shutdown has begun. Callers reachable from goroutines the join does not cover
// (kickUpdateCheck, fired by reconciles) must use this instead of a bare
// bgWG.Add - see bgMu.
func (s *Server) addBackground() bool {
	s.bgMu.Lock()
	defer s.bgMu.Unlock()
	if s.bgStopping {
		return false
	}
	s.bgWG.Add(1)
	return true
}

// stopBackground halts every background service and ticker loop before Start
// returns, so main's deferred sqlite.Close never races goroutines still issuing
// queries. Closing done ends the loops at their next select, and the Wait joins
// them - a loop already mid-body finishes it first (each body is bounded: opCtx
// on the Kea/DB calls, the Commander timeout on shell-outs), so the join is
// bounded too, well inside systemd's stop timeout. The service Stops are
// idempotent, matching the reconciler's own teardown paths.
func (s *Server) stopBackground() {
	s.bgMu.Lock()
	if s.bgStopping {
		s.bgMu.Unlock()
		return // idempotent: a second caller must not close(done) again
	}
	s.bgStopping = true
	close(s.done)
	s.bgMu.Unlock()
	s.bgWG.Wait()
	if s.netmon != nil {
		s.netmon.Stop()
	}
	if s.arp != nil {
		s.arp.Stop()
	}
	if s.ggoscan != nil {
		s.ggoscan.Stop()
	}
	if s.dns != nil {
		s.dns.Stop()
	}
	if s.trunkProbe != nil {
		s.trunkProbe.Stop()
	}
	if s.rogueProbe != nil {
		s.rogueProbe.Stop()
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
		d.Update = s.buildUpdateView() // first paint of the footer badge + its dialogs
		if s.health != nil {
			d.BackendAlerts = s.backendAlertRows() // first paint of the #backend-alert strip (health + preflight)
		}
	}
	if f := s.getFlash(w, r); f != nil {
		d.Flash = &views.Flash{Message: f.Message, Type: f.Type}
		if f.Device != nil {
			d.Flash.Device = &views.FlashDevice{MAC: f.Device.MAC, IP: f.Device.IP, Name: f.Device.Name}
		}
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

// isValidRedirect reports whether p is a root-relative path usable as a
// same-site redirect target: "/x" but not "//host" or "/\host" (browsers
// normalize the backslash into a scheme-relative URL). The name matters:
// CodeQL's open-redirect query only treats a guard as a sanitizer when the
// validation function is named like isLocalUrl/isValidRedirect.
func isValidRedirect(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\")
}

// logSafe strips CR/LF so attacker-supplied values can't forge log lines.
func logSafe(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}

// redirect navigates the client to path: a Datastar SSE redirect for Datastar
// actions, else a plain 302 (native form posts and full page loads).
func (s *Server) redirectHTMX(w http.ResponseWriter, r *http.Request, path string) {
	if !isValidRedirect(path) {
		path = "/"
	}
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
	// Device is set only when the action targeted an online Green-GO device: the next
	// page offers to reboot it to apply the change now (see setFlashDevice).
	Device *FlashDevice `json:"device,omitempty"`
}

// FlashDevice is the reboot-to-apply target carried alongside a flash: the device's
// current address and already-sanitized name (its MAC is kept for reference).
type FlashDevice struct {
	MAC  string `json:"mac,omitempty"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

func (s *Server) setFlash(w http.ResponseWriter, r *http.Request, msg, msgType string) {
	s.writeFlash(w, r, FlashMessage{Message: msg, Type: msgType})
}

// setFlashDevice writes a flash that also carries a reboot-to-apply device context, so
// the next page load can offer to reboot that Green-GO device and apply the change now.
func (s *Server) setFlashDevice(w http.ResponseWriter, r *http.Request, msg, msgType string, dev FlashDevice) {
	s.writeFlash(w, r, FlashMessage{Message: msg, Type: msgType, Device: &dev})
}

func (s *Server) writeFlash(w http.ResponseWriter, r *http.Request, flash FlashMessage) {
	data, _ := json.Marshal(flash)
	// Server-read only (getFlash) - HttpOnly + Strict + Secure like the session
	// cookie (conditional: FACTORY/ONBOARDING runs over plain HTTP on the SoftAP).
	http.SetCookie(w, &http.Cookie{
		Name:     "ggo_flash",
		Value:    hex.EncodeToString(data),
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
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
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	data, err := hex.DecodeString(cookie.Value)
	if err != nil {
		return nil
	}

	var flash FlashMessage
	if err := json.Unmarshal(data, &flash); err != nil {
		// Tolerate a cookie that predates the JSON schema (a bare message string), so
		// an in-flight flash across a deploy still shows rather than being dropped.
		var bare string
		if json.Unmarshal(data, &bare) == nil && bare != "" {
			return &FlashMessage{Message: bare, Type: "info"}
		}
		return nil
	}

	return &flash
}

// toast appends a toast of the given kind ("success"/"error") into the open
// page's live toast region.
func toast(sse *datastar.ServerSentEventGenerator, msg, kind string) {
	_ = sse.PatchElementTempl(views.Toast(msg, kind),
		datastar.WithSelectorID("toast-container"), datastar.WithModeAppend())
}

func (s *Server) handleError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	log.Printf("Error: %s (status code: %d)", logSafe(msg), code)
	if isDatastar(r) {
		// Append an error toast into the live toast region; the page stays put.
		toast(datastar.NewSSE(w, r), msg, "error")
		return
	}
	// A mutating native form post: show the message as an error flash on the page the
	// request came from (post-redirect-get) rather than a bare error page. This is what
	// makes a validation/conflict rejection on a native form (reservations, pinning,
	// settings) read as a toast instead of dumping the operator on a blank page. Falls
	// back to the dashboard when there is no usable same-site Referer.
	//
	// Only for unsafe methods: a GET handler keeps its real status - redirecting a
	// GET error would drop the status code and could loop if the failing page is
	// its own Referer.
	if isUnsafeMethod(r.Method) {
		back := refererPath(r)
		if !isValidRedirect(back) {
			back = "/"
		}
		s.setFlash(w, r, msg, "error")
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

// maxRequestBody bounds every authenticated mutating request's body, applied in
// lifecycleMiddleware before the CSRF check's form parse. Sized to the largest
// legitimate upload (a backup bundle / reservations CSV - see maxBackupUpload).
const maxRequestBody = maxBackupUpload

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

// sameOriginRequest is the pre-session CSRF defense for the FACTORY-state bootstrap
// POSTs (/factory/setup, /factory/restore), which run before any session or CSRF
// token exists. For an unsafe method it requires the Origin (else Referer) header to
// match the request Host. A cross-origin browser POST always carries a mismatched
// Origin and is rejected; a legitimate same-origin submit matches. When both headers
// are absent it fails closed: browsers always send at least one on an unsafe request
// (a fetch/@post sends Origin, a native <form> POST sends Referer), so only header-less
// scripted clients (curl) are blocked.
//
// ACCEPTED RISK (reviewed): a forged Origin defeats this CSRF check, and no in-request
// control can fix that (first-admin creation is unauthenticated by necessity). Accepted
// because FACTORY is not attacker-inducible and short-lived; do not re-file.
func sameOriginRequest(r *http.Request) bool {
	if !isUnsafeMethod(r.Method) {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil {
				origin = u.Scheme + "://" + u.Host
			}
		}
	}
	if origin == "" {
		return false // no Origin/Referer to check - fail closed (browsers always send one)
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
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
			// These POSTs run with no session/CSRF token (no admin exists yet), so a
			// same-origin check is the only CSRF defense available - reject a
			// cross-origin bootstrap/recovery POST before it can create an admin or
			// restore a crafted bundle.
			if !sameOriginRequest(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			// Bound the body like the authenticated branch does: handleFactorySetup
			// ParseForms pre-auth, so without this a SoftAP client could spill a
			// multi-GB body into RAM before any admin exists. handleFactoryRestore also
			// self-caps; this makes the guard uniform across both bootstrap POSTs.
			if isUnsafeMethod(r.Method) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
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
			// Bound the body BEFORE the FormValue fallback below: FormValue parses the
			// whole (multipart) body into RAM and temp files, and this middleware runs
			// ahead of every handler - so this is the appliance's real upload cap. A
			// handler-level MaxBytesReader for a form POST would be dead code (the body
			// is already consumed and the parsed form cached by the time it runs).
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
			provided := r.Header.Get("X-CSRF-Token")
			if provided == "" {
				// Parse explicitly (FormValue swallows parse errors) so an over-cap
				// upload surfaces as 413 rather than a misleading CSRF failure.
				if err := r.ParseMultipartForm(4 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
					if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
						// Route the 413 through the app error path (Datastar toast, or an error
						// flash + redirect back for a native form) so an over-cap upload shows an
						// in-app notification instead of a bare error page.
						s.handleError(w, r, "That file is too large - backups and imports are limited to 8 MB.", http.StatusRequestEntityTooLarge)
						return
					}
				}
				provided = r.FormValue("csrf_token")
			}
			// An empty stored token must never match an empty submission: createSession
			// always sets one, but the sessions read COALESCEs a NULL to "", and an
			// equal-empty compare would otherwise wave a token-less request through.
			if csrfToken == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(csrfToken)) != 1 {
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
		if path == "/setup" || path == "/setup/apply" || strings.HasPrefix(path, "/factory") {
			return "/dashboard"
		}
	case db.StateActive:
		// ACTIVE allows the setup wizard as "create a new configuration" - that is
		// how a second profile (and thus profile switching) becomes reachable. The
		// /factory bootstrap POSTs are the exception: they carry no re-auth and exist
		// only for the pre-auth FACTORY window, so they must not be reachable here.
		if strings.HasPrefix(path, "/factory") {
			return "/dashboard"
		}
	}
	return ""
}
