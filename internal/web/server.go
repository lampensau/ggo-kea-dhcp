package web

import (
	"context"
	"ggo-kea-dhcp/internal/appliance"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
)

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
	// zone owns the local-DNS zone-install discipline: the sampler's idle-rebuild
	// dedup signature and the last-writer-by-generation serialization that keeps a
	// slow detached primeDNSZone from clobbering a fresher zone (see zoneGate).
	zone zoneGate
	// live is the in-process SSE broadcaster pushing state changes to connected
	// operators (lifecycle badge, tiles, lease/learnable lists) without polling.
	live *liveHub
	// mon owns the background network observers (passive monitor, ARP prober,
	// Green-GO scanner, and the onboarding trunk/rogue probes). The reconciler
	// drives their lifecycle; the web layer reads their snapshots. A value, not a
	// pointer: its fields are written once in NewServer and only read afterwards,
	// so the zero value is a usable empty set and a bare &Server{} test double
	// reads through it without a nil check. See monitorSet.
	mon appliance.MonitorSet
	// reservationMu serializes the reservation conflict-check + insert (single add and
	// bulk import) so two concurrent writes can't both pass the check for the same IP
	// and both insert - the hosts unique key does not include ipv4_address, so the DB
	// would not catch it. Single-process, so an in-process mutex is sufficient.
	reservationMu sync.Mutex

	// ggoFw owns the Green-GO firmware-mismatch audit state: the greengo-preset scopes
	// the scanner targets (iface + subnet, refreshed on every startGgoScan, used to
	// attribute findings to the owning scope's Network Health sub-card) and the last
	// audited mismatch census. Scopes are never cleared on Stop - outside ACTIVE netmon
	// is down too, so there are no interface cards to attach to and a stale mapping is
	// inert.
	ggoFw *fwCensus
	// leaseIPs is a single TTL-memoized provider of the active-lease IPs, shared by the
	// ARP prober and the Green-GO scanner so their ~10s cycles collapse to ONE Kea
	// GetLeases round-trip per cycle instead of one each.
	leaseIPs func() []string
	// leaseSrc is the shared short-TTL lease provider every background cadence
	// and display path reads through (see leasecache.go) - the single Kea
	// lease fetcher outside the mutation handlers, which stay direct because
	// they act on the state they read.
	leaseSrc *leaseCache
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
	// reservation can show "last active 3d ago". Primed from SQLite at startup.
	lastSeen *lastSeenTracker
	// lastLeases caches the most recent successful Kea lease fetch so the degraded
	// (Kea-down) live path can keep rendering the periodic regions from known data
	// instead of freezing every region for the whole outage.
	lastLeasesMu sync.Mutex
	lastLeases   []kea.ActiveLease
	// recon is the lifecycle state machine (converge/apply/switch, the mutation
	// guard, the zero-scopes rescue window, the uplink-audit debounce). Built by
	// NewServer from the shared control-plane handles; the handlers drive it
	// through the thin forwarders in reconcile_forward.go, and it reaches back
	// into the web layer only through its nil-tolerant edges (wired in NewServer).
	recon *appliance.Reconciler
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
	// lastUpdateLoadCheck is the unix-nano stamp of the last page-load-triggered
	// update check (kickUpdateCheckOnLoad), for the in-memory attempt-throttle.
	lastUpdateLoadCheck atomic.Int64
	// loginThrottle slows brute-force sign-in attempts with a per-source-IP
	// escalating backoff (throttle-only, never a hard lockout).
	loginThrottle *loginThrottle
	// bg owns the shutdown-join discipline for the background loops (live ticker,
	// metrics sampler, MariaDB probe, update check + kicked checks + result
	// watcher, clock watch): every one registers via bg.add and selects on
	// bg.doneCh, and stopBackground joins them through bg.stop before main's
	// deferred sqlite.Close runs. See bgRunner in bg.go.
	bg *bgRunner
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
	// hwResFetch overrides the hw-address reservation fetch in tests (a counting fake),
	// so the per-broadcast fetch-count invariant is assertable. nil in production, where
	// fetchHWReservationMap reads MariaDB directly.
	hwResFetch func(context.Context) map[string]db.HostReservation
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
	// mon owns the background observers. netmon emits one audit row per confirmed
	// transition (never per tick) via LogAudit and reads its thresholds via
	// GetState - the closures are the only coupling (netmon imports neither web nor
	// db). The audit Result is derived from the event Severity so a rogue-DHCP
	// (error) and a benign notice (warn) read distinctly in the audit log rather
	// than both as free-text "warning". The ARP prober + Green-GO scanner are the
	// ACTIVE-only counterparts; the trunk + rogue-DHCP probes are onboarding-only
	// (started in reconcileOnboarding, stopped on entering ACTIVE).
	s.mon = appliance.MonitorSet{
		Netmon: netmon.NewMonitorManager(sqlite.GetState, func(e netmon.Event) {
			_ = s.sqlite.LogAudit("SYSTEM", e.Action, e.Target, e.Before, e.After, auditResult(e.Severity))
		}),
		Arp:        arpscan.NewProber(),
		Ggoscan:    ggoscan.NewScanner(),
		TrunkProbe: netmon.NewTrunkProbe(),
		RogueProbe: netmon.NewRogueProbe(),
	}
	// The shared lease provider (leasecache.go); every read-through consumer
	// below funnels into this one fetcher.
	s.leaseSrc = newLeaseCache(func(ctx context.Context) ([]kea.ActiveLease, error) {
		return s.kea.GetLeases(ctx, defaultLeasePageSize)
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
	s.health = newBackendHealth()
	s.bg = newBgRunner()
	s.ggoFw = newFwCensus()
	// Build the lifecycle reconciler from the shared control-plane handles, then
	// wire its web-side edges - the ONLY way it reaches SSE, the DNS zone, the
	// update subsystem, the monitor starts, backend-health, and pinning - and arm
	// the boot-only zero-scopes rescue. A nil-tolerant edge fails silently if left
	// unwired, so TestNewServerWiresReconcilerEdges asserts every one is set.
	s.recon = appliance.New(s.cfg, s.sqlite, s.mariadb, s.kea, s.dns, s.net, &s.mon, s.startNetmon, s.startArpProber, s.startGgoScan)
	s.recon.AnnounceUplink = func(down bool, detail string) {
		s.health.setUplinkDown(down, detail)
		s.publishBackendAlert()
	}
	s.recon.PrimeZone = s.primeDNSZone
	s.recon.KickUpdate = s.kickUpdateCheck
	s.recon.ArmRescue()
	// Prime the last-seen tracker from SQLite so a restart doesn't lose history or
	// re-write every row on the first sample.
	s.lastSeen = newLastSeenTracker()
	if ls, err := sqlite.LoadLastSeen(); err == nil {
		s.lastSeen.prime(ls)
	} else {
		log.Printf("[last-seen] prime from SQLite failed: %v", err)
	}
	return s
}

// lastSeenSnapshot returns a copy of the freshest last-seen map (identity -> epoch)
// for the page builders, so a render never holds the lock or races the sampler.
func (s *Server) lastSeenSnapshot() map[string]int64 {
	return s.lastSeen.snapshot()
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
