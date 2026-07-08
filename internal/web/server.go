package web

import (
	"context"
	"log"
	"maps"
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
	// dnsZoneSeq dispenses a monotonic generation to each zone-rebuild dispatch;
	// dnsZoneMu serializes the {generation check + SetZone} so a rebuild that
	// dispatched earlier (a slow detached primeDNSZone) cannot land its staler zone
	// on top of one dispatched later. dnsZoneAppliedGen is the last generation that
	// won, guarded by dnsZoneMu.
	dnsZoneSeq        atomic.Uint64
	dnsZoneMu         sync.Mutex
	dnsZoneAppliedGen uint64
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
	// reservationMu serializes the reservation conflict-check + insert (single add and
	// bulk import) so two concurrent writes can't both pass the check for the same IP
	// and both insert - the hosts unique key does not include ipv4_address, so the DB
	// would not catch it. Single-process, so an in-process mutex is sufficient.
	reservationMu sync.Mutex

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
	s.bg = newBgRunner()
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
