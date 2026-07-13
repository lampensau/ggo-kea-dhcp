package appliance

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/dns"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/network"
)

// ReconcileMode controls how aggressively the Reconciler rebuilds runtime state.
type ReconcileMode int

const (
	// ModeConverge brings runtime state to match the persisted lifecycle state
	// idempotently: no snapshots, no DB writes, and it never tears down working
	// NM connections wholesale (relies on per-connection delete-then-add). Used
	// on boot and for live settings convergence. One exception to the no-writes
	// rule: the boot-only zero-scopes rescue (rescueToOnboarding) persists the
	// ONBOARDING demotion and reconciles with ModeApply semantics - see the
	// rescueArmed window in ReconcileApplianceState.
	ModeConverge ReconcileMode = iota
	// ModeApply is ModeConverge plus a full NM teardown first (so stale scopes
	// from a previous profile are removed). Snapshots are taken by the caller
	// before invoking this (see handleSetupApply), so rollback never depends on
	// querying the DB after a failed apply.
	ModeApply
)

const defaultOnboardingCIDR = "10.0.0.1/24"

// errNoScopes marks the "ACTIVE but nothing to serve" case so the converge
// dispatch can rescue the box to ONBOARDING instead of leaving it addressless.
var errNoScopes = errors.New("no scopes for the active profile")

// softAPWlanIP is the fixed address hostapd assigns to wlan0 in onboarding. Kept
// in sync with softAPWlanCIDR in internal/network/hostapd.go (top corner of the
// 172.16/12 RFC 1918 range, away from the operator subnets on eth0).
const softAPWlanIP = "172.31.255.1"

// reconcileWatchdog bounds how long a background reconcile may run before we log
// that it is still in flight. We cannot cancel it - the underlying nmcli/Kea
// calls are not context-aware - but a log line beats a silent hang.
const reconcileWatchdog = 60 * time.Second

// ReconcilePassDeadline bounds one whole reconcile pass end-to-end: every Kea and
// MariaDB operation inside reconcileActive/reconcileOnboarding shares this
// context. Each individual operation already carries a driver bound (the Kea
// client's 10s HTTP timeout; the MariaDB DSN's 5s dial / 10s read defaults), so
// this is a belt-and-braces ceiling on the pass as a whole - many bounded waits
// and retries stacked in one pass must still release the mutation guard in
// bounded time. Generous on purpose: the privileged commands (nmcli etc.) are
// bounded per-command by the Commander, and a genuinely slow-but-recovering pass
// must not be turned into a rollback.
const ReconcilePassDeadline = 5 * time.Minute

// resumeApplyAttempts / resumeApplyBackoff bound how hard a boot-time resume of an
// interrupted apply retries before falling back to ONBOARDING, so a transient
// cold-boot error (Kea socket / eth0 not up yet) doesn't discard an applied profile.
// Vars (not consts) so tests can shrink the backoff.
var (
	resumeApplyAttempts = 5
	resumeApplyBackoff  = 2 * time.Second
)

// ReconcileBusyMsg is shown when a mutating action is refused because an apply,
// switch, or reconcile already holds the guard.
const ReconcileBusyMsg = "A configuration change is already in progress - try again in a moment."

// Hooks is the Reconciler's only path back to its caller, and so IS the package
// boundary: nothing in here may import the web layer. New takes it as a required
// parameter and reconcileActive/connectUplink call through it unguarded. A test that
// wants no side effects passes an explicit no-op implementation and says so.
type Hooks interface {
	// AnnounceUplink records the uplink's up/down state in backend-health AND
	// re-renders the always-on #backend-alert banner. One method, not two, because
	// they are only ever right together: flipping the state without the push leaves
	// a stale banner on the page the operator has open, and pushing without the
	// state flip renders the old one.
	AnnounceUplink(down bool, detail string)
	// PrimeZone rebuilds the DNS device zone from the freshly-served leases.
	PrimeZone()
	// KickUpdate fires an out-of-band release check when the box gains uplink.
	KickUpdate()
	// The ACTIVE-only observer starts stay with the caller because their spec
	// builders read its lease providers.
	StartNetmon(scopes []ScopeConfig)
	StartArpProber(scopes []ScopeConfig)
	StartGgoScan(scopes []ScopeConfig)
}

// Reconciler owns the lifecycle state machine: it makes runtime network + Kea
// state match the persisted lifecycle state and runs the apply/switch converges.
// It holds only control-plane primitives (config, the two databases, the Kea
// client, DNS, the network manager, the monitor set) plus the mutation guards, and
// reaches its caller only through Hooks.
type Reconciler struct {
	cfg     *config.Config
	sqlite  *db.SQLiteDB
	mariadb *db.MariaDB
	kea     *kea.Client
	dns     *dns.Server
	net     *network.Manager
	mon     *MonitorSet
	// hooks is set once by New and read afterwards from the background goroutines a
	// converge spawns. It is never rebound, so it needs no synchronization.
	hooks Hooks

	// applying guards against concurrent profile applies (a double-submit would
	// otherwise race two reconciles against the live Kea conf).
	applying atomic.Bool
	// rescueArmed opens the zero-scopes rescue window: armed at process start,
	// consumed by the FIRST ACTIVE converge (usually boot). Only inside that window
	// may a nothing-to-serve ACTIVE box demote itself to ONBOARDING - a later
	// converge (a mid-show settings save) must surface the error instead, never
	// tear a serving box down to the SoftAP.
	rescueArmed atomic.Bool
	// uplink debounces the WiFi-uplink audit so a persistently failing or repeatedly
	// re-applied uplink logs exactly one row per real up/down transition (zero value
	// = unknown, so the first connect attempt always audits its outcome).
	uplink uplinkAudit
}

// New builds the lifecycle Reconciler from the caller's shared control-plane handles.
//
// hooks is a parameter rather than a field set afterwards, and has no default: an
// implicit no-op default would restore exactly the failure this design removes - a
// forgotten wire that leaves a silently inert appliance, with the compiler happy. A
// test that wants no side effects passes a no-op implementation on purpose.
//
// The control-plane handles are ALIASED, not owned: the Reconciler reads whatever
// kea/dns/... pointed at when it was built, for the process lifetime. Nothing in
// production rebinds them, so there is one appliance and one guard. Code that does
// rebind one must rebuild the Reconciler, or the two halves diverge - the converge
// tests swap in an httptest Kea and re-call New for exactly that reason.
func New(cfg *config.Config, sqlite *db.SQLiteDB, mariadb *db.MariaDB, keaCli *kea.Client, dnsSrv *dns.Server, netMgr *network.Manager, mon *MonitorSet, hooks Hooks) *Reconciler {
	// Fail fast rather than degrade: a caller that builds the Reconciler before it has
	// set one of these handles would otherwise drive a different appliance than the one
	// it renders from, silently. mariadb is the one legitimate nil (a documented
	// degraded mode - dynamic leases keep serving without host reservations).
	switch {
	case cfg == nil:
		panic("appliance.New: nil config")
	case sqlite == nil:
		panic("appliance.New: nil sqlite")
	case keaCli == nil:
		panic("appliance.New: nil kea client")
	case dnsSrv == nil:
		panic("appliance.New: nil dns server")
	case netMgr == nil:
		panic("appliance.New: nil network manager")
	case mon == nil:
		panic("appliance.New: nil monitor set")
	case hooks == nil:
		// Catches a literal nil only; a typed-nil pointer in an interface is not nil
		// here and would panic at the first call instead. Loudly, either way.
		panic("appliance.New: nil hooks")
	}
	return &Reconciler{
		cfg:     cfg,
		sqlite:  sqlite,
		mariadb: mariadb,
		kea:     keaCli,
		dns:     dnsSrv,
		net:     netMgr,
		mon:     mon,
		hooks:   hooks,
	}
}

// ArmRescue opens the boot-only zero-scopes rescue window. Called once, by the
// caller's constructor path, before any converge runs: only inside that window may a
// nothing-to-serve ACTIVE box demote itself to ONBOARDING.
func (r *Reconciler) ArmRescue() { r.rescueArmed.Store(true) }

// IsApplying reports whether a mutation path currently holds the guard. For tests and
// for the handlers that refuse a concurrent apply; claiming it is BeginReconcile's job.
func (r *Reconciler) IsApplying() bool { return r.applying.Load() }

// BeginReconcile claims the single appliance-mutation guard shared by every path
// that rewrites kea-dhcp4.conf / the lifecycle state (apply, switch, settings,
// reset, pools, restore). It returns false when another such path is already
// running, so the caller can refuse instead of racing a second reconcile against
// the live config. On success the caller OWNS the guard and must release it -
// EndReconcile for synchronous work, or hand it to ScheduleReconcileHeld which
// releases it when the background reconcile finishes.
func (r *Reconciler) BeginReconcile() bool { return r.applying.CompareAndSwap(false, true) }

// EndReconcile releases the guard claimed by BeginReconcile.
func (r *Reconciler) EndReconcile() { r.applying.Store(false) }

// ScheduleReconcileHeld runs a reconcile in the background after an optional delay
// (which lets an already-flushed interstitial reach the client before links drop),
// then releases the guard the caller MUST already hold (via BeginReconcile). This
// is the single entry point for the fire-and-forget reconciles triggered by
// settings saves and resets - serialized against apply/switch by the shared guard.
func (r *Reconciler) ScheduleReconcileHeld(label string, delay time.Duration, mode ReconcileMode, profileID int) {
	go r.RunRecoveredAudited("reconcile-"+label, func() {
		defer r.EndReconcile()
		if delay > 0 {
			time.Sleep(delay)
		}
		wd := time.AfterFunc(reconcileWatchdog, func() {
			log.Printf("[reconcile:%s] still running after %s", label, reconcileWatchdog)
		})
		// Deferred: a recovered panic must not leak the armed watchdog, which
		// would log a false "still running" right after the PANIC_RECOVERED row.
		defer wd.Stop()
		err := r.ReconcileApplianceState(mode, profileID)
		if err != nil {
			// Audit, not just stderr: these run detached from any request (settings
			// save, reset, restore), so this row - surfaced on Diagnostics - is the
			// only way the operator learns the convergence failed.
			log.Printf("[reconcile:%s] reported: %v", label, err)
			_ = r.sqlite.LogAudit("SYSTEM", "RECONCILE_FAILED", label, "", err.Error(), "WARNING")
		}
	})
}

// ReconcileApplianceState is the single authority that makes runtime network +
// Kea state match the persisted lifecycle state. targetProfileID==0 means "use
// the active profile" (only relevant in ACTIVE).
func (r *Reconciler) ReconcileApplianceState(mode ReconcileMode, targetProfileID int) error {
	state, _ := r.sqlite.GetState(db.LifecycleStateKey)
	if state == "" {
		state = db.StateFactory
	}

	// The zero-scopes rescue window is consumed by the FIRST reconcile after
	// process start regardless of its state - truly boot-only. A box that boots
	// into ONBOARDING/FACTORY (or resumes an apply) never needs the rescue
	// later; leaving the window armed through such a boot let the first
	// post-apply settings converge demote a serving box whose rows were lost
	// after boot. Only a box that WAKES UP claiming ACTIVE with nothing to
	// serve may demote itself; every later zero-scopes converge surfaces the
	// error instead of tearing a venue network down.
	rescueOpen := r.rescueArmed.CompareAndSwap(true, false)

	// A box found persisted in CONFIGURING during a converge (boot/settings - not
	// the apply goroutine's own ModeApply) had its apply interrupted. Complete it
	// rather than reconcile blindly (see resumeInterruptedApply).
	if interruptedMidApply(state, mode) {
		return r.resumeInterruptedApply(targetProfileID)
	}

	switch state {
	case db.StateActive, db.StateConfiguring:
		// ACTIVE and a live-apply CONFIGURING both serve the profile's scopes.
		err := r.reconcileActive(mode, targetProfileID)
		if rescueOpen && mode == ModeConverge && state == db.StateActive {
			if errors.Is(err, errNoScopes) {
				return r.rescueToOnboarding(err)
			}
			// Sweep a rollback stash orphaned by a crash between finishApply's ACTIVE
			// write and its stash DELETE: that box boots straight into ACTIVE (never the
			// CONFIGURING-resume path that also sweeps), so without this the hidden
			// active=0 stash row + scopes leak forever. Boot-only (rescueOpen) and
			// success-only, so it never races an in-flight apply's live rollback stash.
			if err == nil {
				if e := r.SweepOrphanedStashes(); e != nil {
					log.Printf("[reconcile] failed to sweep orphaned stash on ACTIVE boot: %v", e)
				}
			}
		}
		return err
	default: // FACTORY and ONBOARDING share identical network state.
		return r.reconcileOnboarding(mode)
	}
}

// rescueToOnboarding demotes a box that claims ACTIVE but has nothing to serve
// (zero scopes - e.g. a corrupted or hand-edited profile row) back to ONBOARDING
// so the SoftAP and onboarding IP come up. Without this the converge fails before
// any interface is configured and the box is unreachable except by console.
// Converge-only: the apply/switch paths (ModeApply) have their own rollback and
// must see the error, not a silent demotion.
func (r *Reconciler) rescueToOnboarding(cause error) error {
	log.Printf("[reconcile] %v - falling back to ONBOARDING so the box stays reachable", cause)
	_ = r.sqlite.LogAudit("SYSTEM", "RESCUE_ONBOARDING", "lifecycle", "", cause.Error(), "WARNING")
	if e := r.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding); e != nil {
		log.Printf("[reconcile] failed to persist ONBOARDING on rescue: %v", e)
	}
	// ModeApply so stale NM connections from the dead profile are torn down, same
	// as resumeInterruptedApply's fallback. That mode also wipes the lease store -
	// deliberate: the leases belong to the profile that just proved unservable,
	// and the onboarding pool must not inherit them. A backup restored later
	// re-creates reservations; dynamic leases re-acquire on their own.
	return r.reconcileOnboarding(ModeApply)
}

// resumeInterruptedApply completes a profile apply that was interrupted (the box
// was found persisted in CONFIGURING at boot/converge, with no apply goroutine
// running). It brings the active profile fully up; on success it finalizes the
// ACTIVE state the apply goroutine never reached, and only on a *failed* reconcile
// does it fall back to ONBOARDING. This deliberately COMPLETES rather than
// discards - covering both a genuinely half-applied box and one whose apply
// succeeded but whose ACTIVE state-write was interrupted (reconcile is idempotent
// and re-validates the config, so finishing is safe).
func (r *Reconciler) resumeInterruptedApply(profileID int) error {
	log.Printf("[reconcile] found %s at converge - completing the interrupted apply", db.StateConfiguring)
	// Retry with backoff before giving up: on a cold boot the Kea control socket or
	// eth0 link may not be up yet, and reconcileActive folds such transient errors in
	// with errors.Join. Reverting a profile that was actually applied back to
	// ONBOARDING on a transient boot hiccup would dump the operator to the SoftAP
	// mid-deployment, so we re-try (reconcile is idempotent) before falling back.
	// ModeApply, not Converge: the interrupted apply may have replaced a profile
	// whose scopes the new one lacks, and only the full NM teardown evicts those
	// stale connections (NM autoconnects them on boot and they would be re-IP'd,
	// diverging from the served subnets). Idempotent, so retrying with it is safe.
	var err error
	for attempt := 1; attempt <= resumeApplyAttempts; attempt++ {
		if err = r.reconcileActive(ModeApply, profileID); err == nil {
			break
		}
		log.Printf("[reconcile] resume attempt %d/%d did not complete: %v", attempt, resumeApplyAttempts, err)
		if attempt < resumeApplyAttempts {
			time.Sleep(resumeApplyBackoff)
		}
	}
	if err != nil {
		log.Printf("[reconcile] could not complete interrupted apply after %d attempts (%v) - reverting to ONBOARDING", resumeApplyAttempts, err)
		if e := r.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding); e != nil {
			log.Printf("[reconcile] failed to persist ONBOARDING on revert: %v", e)
		}
		// ModeApply for the same reason as above: the half-applied profile's VLAN
		// connections must not linger into onboarding.
		return r.reconcileOnboarding(ModeApply)
	}
	if e := r.sqlite.SetState(db.LifecycleStateKey, db.StateActive); e != nil {
		log.Printf("[reconcile] completed interrupted apply but failed to persist ACTIVE: %v", e)
	}
	// Drop any profile that persistProfile renamed aside as a rollback stash: a
	// crash between persistProfile and finishApply leaves one behind, and the
	// apply we just completed made the new profile authoritative.
	if e := r.SweepOrphanedStashes(); e != nil {
		log.Printf("[reconcile] failed to sweep orphaned apply stash: %v", e)
	}
	return nil
}

// SweepOrphanedStashes drops any rollback-stash profile (persistProfile renames a
// replaced same-named profile aside as "<name>.stash-<id>", always active = 0) that a
// crash between persistProfile and finishApply left behind. The active = 0 guard means
// it can never delete a live profile. Idempotent; excluded from the switcher too (see
// listProfiles). Returns the error for the caller to log.
func (r *Reconciler) SweepOrphanedStashes() error {
	_, err := r.sqlite.Exec("DELETE FROM profiles WHERE active = 0 AND name GLOB '*.stash-[0-9]*'")
	return err
}

// interruptedMidApply reports whether the appliance was found mid-apply at boot:
// the persisted CONFIGURING marker during a converge (boot/settings) rather than
// the ModeApply call the apply goroutine itself makes.
func interruptedMidApply(state string, mode ReconcileMode) bool {
	return state == db.StateConfiguring && mode == ModeConverge
}

// StopActiveMonitors tears down every ACTIVE-only background service: the passive
// network monitor, the ARP presence prober, the Green-GO scanner, and the port-53
// DNS listeners (bound to the outgoing profile's scope addresses, so they must
// drop before any re-IP; reconcileActive rebinds on the new addresses). The single
// teardown used by every ACTIVE-exit path - finishApply, beginSwitch,
// reconcileOnboarding, and process shutdown (stopBackground) - so a lifecycle fix
// cannot land in one path and strand the others. All stops are idempotent and nil-safe.
func (r *Reconciler) StopActiveMonitors() {
	r.mon.StopActive()
	if r.dns != nil {
		r.dns.Stop()
	}
}

// reconcileOnboarding brings up the onboarding environment: eth0 management IP,
// wlan0 SoftAP, torn-down NAT, and the ungrouped dynamic Kea scope. No captive DNS
// redirector runs here - it is only stopped (see the no-DNS note below).
func (r *Reconciler) reconcileOnboarding(mode ReconcileMode) error {
	ctx, cancel := context.WithTimeout(context.Background(), ReconcilePassDeadline)
	defer cancel()
	var errs []error
	cidr := r.OnboardingCIDR()
	ssid, pass := r.SoftAPSettings()

	if mode == ModeApply {
		_ = r.net.DeleteApplianceConnections()
	}

	if err := r.net.SetInterfaceStatic("eth0", cidr); err != nil {
		errs = append(errs, fmt.Errorf("eth0 static: %w", err))
	}
	// Onboarding ALWAYS raises the SoftAP: it is the operator's guaranteed way in when a
	// reset drops them here with no other access (an in-place "Edit Configuration" from
	// ACTIVE never reaches this path - it applies via reconcileActive, which tears the
	// SoftAP down). StartSoftAP flushes wlan0 first, so a prior uplink address can't linger
	// and shadow the SoftAP's own DHCP.
	_ = r.net.SetInterfaceManaged("wlan0", false)
	if err := r.net.StartSoftAP(ssid, pass); err != nil {
		errs = append(errs, fmt.Errorf("softap: %w", err))
	}

	// Leaving ACTIVE: stop the passive monitor, ARP prober, Green-GO scanner, and the
	// port-53 listeners (no DNS is served during onboarding - see the no-DNS note
	// below). Idempotent if nothing runs.
	r.StopActiveMonitors()
	// Onboarding-only: passively sniff eth0 for tagged VLANs so the wizard's link badge can
	// tell the operator the switch port is a trunk. Best-effort (no CAP_NET_RAW -> inert).
	if r.mon.TrunkProbe != nil {
		r.mon.TrunkProbe.Start("eth0")
	}
	// Onboarding-only: watch eth0 for a DHCP server already answering, so the wizard's
	// shield badge names it before the operator applies. Best-effort like the trunk probe.
	// The box serves its own onboarding pool on eth0; Start reads eth0's MAC and suppresses
	// the box's own OFFERs by source MAC, so the probe never flags the appliance itself.
	if r.mon.RogueProbe != nil {
		r.mon.RogueProbe.Start("eth0")
	}

	// Onboarding never routes - make sure no NAT state leaks in from a prior gig.
	_ = r.net.SetIPForwarding(false)
	_ = r.net.ApplyMasquerade("wlan0", false)
	_ = r.net.ClearPortForwards()

	// No captive DNS redirect and no DHCP gateway/DNS handout during onboarding: that
	// made connected PCs route their (non-existent) internet through the box and tripped
	// the OS captive-portal assistant into a self-signed-cert loop. Clients reach the box
	// on its own same-subnet address. wlanIP is still needed for the onboarding Kea scope.
	wlanIP := ""
	if _, err := net.InterfaceByName("wlan0"); err == nil {
		wlanIP = softAPWlanIP
	}

	// Onboarding Kea config. Deliberately carries NO MariaDB backend (see
	// RenderOnboarding): eth0 DHCP must come up regardless of MariaDB state.
	cfgStr, _, err := kea.RenderOnboarding(kea.OnboardingInput{
		EthCIDR:       cidr,
		WlanIP:        wlanIP,
		KeaSecretPath: r.cfg.KeaSecretPath,
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("render onboarding: %w", err))
	} else if werr := r.WriteAndReloadKea(ctx, cfgStr); werr != nil {
		errs = append(errs, werr)
	} else if mode == ModeApply {
		// A reset (ModeApply) must not inherit the prior job's leases: the memfile lease
		// store survives a config reload, so stale leases - and the learnable ports derived
		// from them - would otherwise persist. Wipe now that Kea is up with the onboarding
		// config. Best-effort: a wipe failure must not fail the reset. (A first onboarding
		// has no leases, so this is a harmless no-op there.)
		if werr := r.kea.WipeLeases(ctx); werr != nil {
			log.Printf("[Reconcile] onboarding lease wipe failed: %v", werr)
		}
	}

	return errors.Join(errs...)
}

// reconcileActive brings up all served interfaces, renders+reloads the profile
// Kea config, and applies (or tears down) uplink NAT.
func (r *Reconciler) reconcileActive(mode ReconcileMode, profileID int) error {
	ctx, cancel := context.WithTimeout(context.Background(), ReconcilePassDeadline)
	defer cancel()
	var errs []error

	// Leaving onboarding: the trunk and rogue-DHCP probes are onboarding-only hints, and
	// ACTIVE has the full passive monitor for VLAN reality and rogue servers. (The trunk
	// probe's last-seen VLANs are snapshotted at apply.)
	r.mon.StopOnboarding()

	scopes, err := r.LoadScopeConfigs(profileID)
	if err != nil {
		return fmt.Errorf("active reconcile: load scopes: %w", err)
	}
	if len(scopes) == 0 {
		return fmt.Errorf("active reconcile: %w", errNoScopes)
	}

	// Kea subnet-ids are positional, so a profile edit/switch renumbers them while
	// host reservations/pins keep the id stamped at creation. Re-derive every host
	// row's subnet-id from its IP over these scopes before the new config serves
	// (Kea reads the host rows live). Best-effort: MariaDB may be down and DHCP
	// must still come up. Deliberately ahead of the render/validate below: a render
	// that fails here re-stamps rows for a config that won't load, but the next
	// reconcile re-derives them, and a reconcile-time validation failure is
	// environmental (every reconcile would fail, not just this one).
	r.RemapReservationSubnets(ctx, scopes, mode)

	if mode == ModeApply {
		_ = r.net.DeleteApplianceConnections()
	}

	anyScopeUplink := false
	for _, sc := range scopes {
		_, ipnet, perr := net.ParseCIDR(sc.CIDR)
		if perr != nil {
			errs = append(errs, fmt.Errorf("scope %s: %w", sc.CIDR, perr))
			continue
		}
		maskSize, _ := ipnet.Mask.Size()
		staticCIDR := fmt.Sprintf("%s/%d", kea.IncIP(ipnet.IP, 1).String(), maskSize)
		if sc.VlanID == 0 {
			if e := r.net.SetInterfaceStatic("eth0", staticCIDR); e != nil {
				errs = append(errs, fmt.Errorf("eth0 static: %w", e))
			}
		} else {
			if e := r.net.SetVlanStatic("eth0", sc.VlanID, staticCIDR); e != nil {
				errs = append(errs, fmt.Errorf("vlan %d static: %w", sc.VlanID, e))
			}
		}
		if sc.Uplink.Enabled {
			anyScopeUplink = true
		}
	}

	// Box-level WiFi uplink (one wlan0): the master enable + credentials live in
	// app_state. We connect wlan0 and masquerade only when the uplink is enabled AND
	// at least one scope is toggled to route through it. WHICH scope advertises the
	// gateway is the renderer's job (per-scope toggle, gated by the master enable).
	boxUplinkEnabled, upSSID, upPass := r.UplinkSettings()
	hasUplink := boxUplinkEnabled && anyScopeUplink && upSSID != ""

	// Active mode: tear down onboarding-only services. (The port-53 server is
	// rebound below via StartZone, which stops any prior listeners itself.)
	_ = r.net.StopSoftAP()
	_ = r.net.SetInterfaceManaged("wlan0", true)

	// Render + write + reload Kea from the scopes already loaded above (no second
	// DB load / JSON unmarshal). KeaConfigForState honors a persisted operator
	// stand-down: while stood down it renders the holdoff config (Kea reachable but
	// serving no subnet), so a reboot mid-conflict does not silently resume serving.
	reloadOK := false
	cfgStr, rerr := r.KeaConfigForState(scopes)
	if rerr != nil {
		errs = append(errs, fmt.Errorf("render profile: %w", rerr))
	} else if werr := r.WriteAndReloadKea(ctx, cfgStr); werr != nil {
		errs = append(errs, werr)
	} else {
		reloadOK = true
	}

	if e := r.applyNAT(hasUplink); e != nil {
		errs = append(errs, e)
	}

	// WiFi uplink: (re)connect (slow, only when needed and not already up) using the
	// box-level credentials (one wlan0); or tear the connection down when nothing routes
	// through it (master off, or no scope toggled), so disabling the uplink in Settings
	// actually drops wlan0 - converge fully owns the uplink state.
	switch {
	case hasUplink && !r.net.IsWifiUplinkActive():
		go r.RunRecoveredAudited("uplink-connect", func() { r.connectUplink(upSSID, upPass) })
	case !hasUplink:
		_ = r.net.DisconnectWifiUplink()
	}

	// Now the new class guards are live, relocate any device sitting in the wrong pool
	// (e.g. a beltpack that earlier landed in a catch-all) into its own device-class
	// pool when that pool has room - by releasing the stale lease so it re-DHCPs.
	// Best-effort; gated on a successful reload so we never act against a config Kea
	// did not accept. Skipped while stood down - the holdoff config serves no pool,
	// so there is nothing to rebalance into.
	if reloadOK && !r.DHCPStoodDown() {
		r.rebalanceLeases(ctx, scopes)
	}

	// Passive network-health monitoring AND the active ARP presence prober run only in
	// ACTIVE: this is their sole Start site, reached once the served interfaces are up.
	// Best-effort - both launch goroutines, never error, and so cannot affect the
	// reconcile outcome (errs above), keeping the core apply path isolated.
	r.hooks.StartNetmon(scopes)
	r.hooks.StartArpProber(scopes)
	r.hooks.StartGgoScan(scopes)
	// ACTIVE-only: the port-53 owner serves the device zones, one socket per served
	// scope's own address (never wlan0) so each apex answer names the address that
	// segment can reach. Best-effort like the monitors; the zone primes in the
	// background and then follows the dashboard cadence (rebuildDNSZone).
	if r.dns != nil {
		var bindIPs, cidrs []string
		for _, sc := range scopes {
			if _, ipnet, e := net.ParseCIDR(sc.CIDR); e == nil {
				bindIPs = append(bindIPs, kea.IncIP(ipnet.IP, 1).String())
				cidrs = append(cidrs, sc.CIDR)
			}
		}
		// Served subnets first, so a PTR that arrives the instant a listener binds
		// is already answered authoritatively rather than forwarded.
		r.dns.SetServedSubnets(cidrs)
		// StartZone runs inline (single-attempt binds, no sleeps), so it is ordered
		// with respect to this and every other reconcile - a stale background start
		// can never clobber a newer listener set. A bind that fails because its
		// address is not up yet is audited and left to healDNSBinds (the sampler's
		// self-heal). Only the zone prime, which hits Kea for leases, is backgrounded
		// so it never stalls the reconcile; it just swaps zone content atomically.
		for _, ip := range r.dns.StartZone(bindIPs) {
			_ = r.sqlite.LogAudit("SYSTEM", "DNS_BIND_FAILED", ip, "", "port 53 bind failed, retrying on the sampler tick", "WARNING")
		}
		go r.RunRecoveredAudited("dns-zone-prime", r.hooks.PrimeZone)
	}

	return errors.Join(errs...)
}

// uplinkAudit debounces the WiFi-uplink up/down audit. Unlike Kea/MariaDB (which have
// a periodic probe) connectUplink is the only observer and runs on demand (reconcile /
// Settings save), so a persistently broken uplink would otherwise log a fresh
// UPLINK_DOWN on every reconcile and a re-saved working uplink a fresh UPLINK_UP on
// every save. A simple last-state transition guard collapses that to one row per real
// transition - no consecutive-fail threshold (that is for noisy periodic probes).
type uplinkAudit struct {
	mu      sync.Mutex
	known   bool // false until the first observation
	healthy bool
}

// observe records one up/down sample and reports whether it changed the state (i.e.
// whether this outcome should be audited). The first observation always counts.
func (u *uplinkAudit) observe(ok bool) (changed bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.known && u.healthy == ok {
		return false
	}
	u.known = true
	u.healthy = ok
	return true
}

// connectUplink performs the slow WiFi association off the reconcile path. If a
// reset/rollback returned the box to onboarding while we were connecting, it
// tears the just-(re)created uplink back down so a late goroutine can't leave a
// stale uplink active after teardown.
func (r *Reconciler) connectUplink(ssid, pwd string) {
	if e := r.net.SetWifiUplink(ssid, pwd); e != nil {
		log.Printf("Warning: WiFi uplink connect failed: %v", e)
		// Surface the failure the way Kea/MariaDB outages are (onBackendChange):
		// a SYSTEM audit event so it appears on the Audit Log and Diagnostics, not
		// just stderr. WARNING, not ERROR - DHCP still serves locally, only the
		// upstream is lost. The detail carries nmcli's reason (e.g. bad password /
		// SSID not found), so "the SSID or password is wrong" finally reaches the UI.
		// Debounced: only the down transition is logged, not every retry.
		if r.uplink.observe(false) {
			_ = r.sqlite.LogAudit("SYSTEM", "UPLINK_DOWN", ssid, "", e.Error(), "WARNING")
		}
		// Surface it to whatever page the operator has open NOW (not just the Audit
		// Log): the connect runs in a background goroutine, so the Settings save that
		// triggered it already returned "saved". The always-on #backend-alert banner
		// carries nmcli's reason so "the SSID or password is wrong" reaches the UI.
		r.hooks.AnnounceUplink(true, "Wi-Fi uplink: "+e.Error())
		return
	}
	if st, _ := r.sqlite.GetState(db.LifecycleStateKey); st != db.StateActive && st != db.StateConfiguring {
		log.Printf("[uplink] appliance left the active state (%s) during connect - tearing down stale uplink", st)
		_ = r.net.DisconnectWifiUplink()
		// Deliberate teardown (not a failure), so it is not audited - but mark the link
		// down so a genuine re-connect after the box returns to ACTIVE audits UPLINK_UP.
		r.uplink.observe(false)
		r.hooks.AnnounceUplink(false, "") // not a failure - clear any prior alert
		return
	}
	// Debounced: log UPLINK_UP only on an actual down->up (or first) transition, so a
	// re-saved unchanged uplink does not spam the Audit Log.
	if r.uplink.observe(true) {
		_ = r.sqlite.LogAudit("SYSTEM", "UPLINK_UP", ssid, "", "connected", "OK")
	}
	// The box just gained internet - the one moment a release check is worth
	// kicking rather than waiting out the 30-min ticker.
	r.hooks.KickUpdate()
	r.hooks.AnnounceUplink(false, "") // connected - clear the banner
}

// applyNAT enables masquerade + forwarding when any scope has an uplink, and
// fully tears it down otherwise. Idempotent (ApplyMasquerade flushes first).
func (r *Reconciler) applyNAT(hasUplink bool) error {
	var errs []error
	if hasUplink {
		if e := r.net.SetIPForwarding(true); e != nil {
			errs = append(errs, fmt.Errorf("ip_forward on: %w", e))
		}
		if e := r.net.ApplyMasquerade("wlan0", true); e != nil {
			errs = append(errs, fmt.Errorf("masquerade on: %w", e))
		}
		_ = r.net.ClearPortForwards() // no port-forward model yet; keep clean
	} else {
		_ = r.net.SetIPForwarding(false)
		_ = r.net.ApplyMasquerade("wlan0", false)
		_ = r.net.ClearPortForwards()
	}
	return errors.Join(errs...)
}

// RenderKeaForScopes renders the profile Kea config from already-loaded scopes
// (the caller loads them once and passes them in, avoiding a second DB read +
// JSON unmarshal on the boot/converge critical path).
// BaseRenderInput assembles the ProfileRenderInput fields shared by every render path -
// the MariaDB DSN split, the Kea secret path, and the global DHCP options. Each caller
// then sets Scopes plus its path-specific fields (LeaseLifetime for the served reconcile,
// IfaceWildcard for the apply/switch validation renders) before calling RenderProfile.
func (r *Reconciler) BaseRenderInput() kea.ProfileRenderInput {
	host, user, pass, name := config.ParseMariaDSN(r.cfg.MariaDBDSN)
	g := r.GlobalDHCPOptionsFor()
	return kea.ProfileRenderInput{
		MariaDBHost:   host,
		MariaDBUser:   user,
		MariaDBPass:   pass,
		MariaDBName:   name,
		KeaSecretPath: r.cfg.KeaSecretPath,
		GlobalDNS:     g.DNS,
		GlobalOptions: g.keaOptions(),
	}
}

func (r *Reconciler) RenderKeaForScopes(scopes []ScopeConfig) (string, []string, error) {
	if len(scopes) == 0 {
		return "", nil, fmt.Errorf("no scopes for profile")
	}

	in := r.BaseRenderInput()
	in.LeaseLifetime = r.LeaseLifetime()
	boxUplink, _, _ := r.UplinkSettings()
	for _, sc := range scopes {
		ri := sc.ToRenderInput()
		// A scope advertises the uplink gateway only when its toggle is on AND the
		// box-level master enable is on - master off means no scope routes (no dead
		// default route on a box with the uplink switched off).
		ri.Uplink = ri.Uplink && boxUplink
		in.Scopes = append(in.Scopes, ri)
	}
	return kea.RenderProfile(in)
}

// SnapshotKeaConf copies the current live Kea config into the snapshot directory
// and records it, returning the snapshot path for rollback. A missing live conf
// (first apply) is not an error and returns an empty path.
func (r *Reconciler) SnapshotKeaConf(reason string) (string, error) {
	live := filepath.Join(r.cfg.KeaConfDir, "kea-dhcp4.conf")
	data, err := os.ReadFile(live)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read live kea conf: %w", err)
	}
	if err := os.MkdirAll(r.cfg.SnapshotDir, 0700); err != nil {
		return "", fmt.Errorf("create snapshot dir: %w", err)
	}
	path := filepath.Join(r.cfg.SnapshotDir, fmt.Sprintf("kea-dhcp4.%d.conf", time.Now().UnixNano()))
	if err := WriteFileSync(path, data, 0600); err != nil {
		return "", fmt.Errorf("write snapshot: %w", err)
	}
	// The snapshot file is on disk; a failed index insert only hides it from the
	// rollback/listing UI. Log so it is not a silent gap.
	if _, err := r.sqlite.Exec("INSERT INTO config_snapshots (reason, path) VALUES (?, ?)", reason, path); err != nil {
		log.Printf("[snapshot] wrote %s but failed to index it: %v", path, err)
	}
	return path, nil
}

// WriteFileSync writes path in place (truncate + write + fsync), returning the
// error from every step including Sync and the success-path Close. Deliberately
// NOT temp-file+rename: /etc/kea is 0750 and root-owned - the service user owns
// the conf file itself but cannot create files in the directory, so an atomic
// rename is impossible there. The fsync closes the durability gap (a power loss
// after a successful apply can no longer lose the config); the residual torn-write
// window (crash mid-write) self-heals on the next reconcile, which re-renders from
// SQLite and overwrites this file - it only bites if Kea itself restarts first.
func WriteFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// WriteAndReloadKea validates, writes the rendered config to the live path, and
// reloads Kea. Validation happens before the live file is touched so a bad
// render can't take Kea down on reload - this covers the boot/settings/reset
// converge paths that don't go through handleSetupApply's own pre-apply check.
// ctx bounds the Kea control-socket calls (the reconcile pass deadline).
func (r *Reconciler) WriteAndReloadKea(ctx context.Context, configStr string) error {
	if err := kea.TestConfig(configStr); err != nil {
		return fmt.Errorf("kea config validation failed: %w", err)
	}
	live := filepath.Join(r.cfg.KeaConfDir, "kea-dhcp4.conf")
	if err := WriteFileSync(live, []byte(configStr), 0660); err != nil {
		return fmt.Errorf("write kea conf: %w", err)
	}
	if err := r.kea.ReloadConfig(ctx); err != nil {
		// If the control socket itself was unreachable (transport refused, not a
		// command-level rejection), Kea is running a config without the :8004 HTTP
		// socket - and config-reload can never recover that, because it needs :8004.
		// Restart Kea so it re-reads the file we just wrote (which always carries the
		// :8004 socket), then re-probe. Guarded by Installed() so a dev sandbox with
		// no Kea keeps the old fast-fail behaviour instead of waiting on a no-op
		// restart.
		if !r.kea.Reachable() && kea.Installed() {
			log.Printf("[kea] control socket unreachable on reload - restarting %s to load the on-disk config", keaServiceName)
			if rerr := r.net.RestartService(keaServiceName); rerr != nil {
				return fmt.Errorf("reload kea: socket unreachable and restart failed: %v (reload: %w)", rerr, err)
			}
			// The restart already made the on-disk config live, so the liveness probe
			// gets its own small budget rather than the pass ctx: near the pass
			// deadline an inherited ctx would fail this probe instantly and report a
			// spurious failure (in an apply, a rollback) over a load that succeeded.
			probeCtx, probeCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer probeCancel()
			if perr := r.waitKeaReachable(probeCtx, 5, time.Second); perr != nil {
				return fmt.Errorf("reload kea: restarted %s but it is still unreachable: %w", keaServiceName, perr)
			}
			// The restart re-read our file, so the new config is now live - no second
			// reload needed.
			log.Printf("[kea] %s restarted and reachable - config applied", keaServiceName)
			return nil
		}
		return fmt.Errorf("reload kea: %w", err)
	}
	return nil
}

// keaServiceName is the systemd unit that runs kea-dhcp4 (the ISC Debian package).
const keaServiceName = "isc-kea-dhcp4-server"

// waitKeaReachable polls Kea's control socket until it answers, the attempts run
// out, or ctx expires - returning the last probe error.
func (r *Reconciler) waitKeaReachable(ctx context.Context, attempts int, delay time.Duration) error {
	var err error
	for range attempts {
		if err = r.kea.Ping(ctx); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		time.Sleep(delay)
	}
	return err
}

// --- app_state-backed settings with defaults ---

func (r *Reconciler) OnboardingCIDR() string {
	if v, _ := r.sqlite.GetState("onboarding_ip"); v != "" {
		return v
	}
	return defaultOnboardingCIDR
}

func (r *Reconciler) SoftAPSettings() (ssid, pass string) {
	ssid, _ = r.sqlite.GetState("softap_ssid")
	if ssid == "" {
		ssid = "GGO-DHCP-Onboarding"
	}
	pass, _ = r.sqlite.GetState("softap_pass")
	return ssid, pass
}

// UplinkSettings returns the box-level WiFi uplink config (one wlan0): the master
// enable plus the SSID/password handed to NetworkManager, from app_state. WHICH scopes
// route through the uplink is the per-scope toggle (ScopeConfig.Uplink.Enabled); this
// master enable governs the whole uplink - off means no scope routes, full stop.
func (r *Reconciler) UplinkSettings() (enabled bool, ssid, pass string) {
	e, _ := r.sqlite.GetState("uplink_enabled")
	ssid, _ = r.sqlite.GetState("uplink_ssid")
	pass, _ = r.sqlite.GetState("uplink_pass")
	return e == "1", ssid, pass
}

// MigrateUplinkToBoxLevel seeds the box-level uplink app_state keys from a legacy
// per-scope uplink_json once (the pre-box-level model), so an upgraded box keeps its
// configured uplink. No-op once a box-level key exists.
func (r *Reconciler) MigrateUplinkToBoxLevel() {
	if v, _ := r.sqlite.GetState("uplink_ssid"); v != "" {
		return
	}
	if v, _ := r.sqlite.GetState("uplink_enabled"); v != "" {
		return
	}
	_, cfg, ok := r.activeProfileUplink()
	if !ok || cfg.SSID == "" {
		return
	}
	if err := r.sqlite.SetStates(UplinkState(cfg.Enabled, cfg.SSID, cfg.Password)); err != nil {
		log.Printf("[migrate] seed box-level uplink: %v", err)
		return
	}
	log.Printf("[migrate] seeded box-level WiFi uplink from legacy per-scope config")
}

// LeaseLifetime returns the active-profile DHCP lease lifetime in seconds: the operator's
// saved Settings value (app_state "lease_lifetime") when set and valid, else the
// --lease-lifetime flag default. Settings is the single source of truth; the flag is only
// the fallback.
func (r *Reconciler) LeaseLifetime() int {
	if v, _ := r.sqlite.GetState("lease_lifetime"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return r.cfg.LeaseLifetime
}

// IPOnly strips a /mask suffix, returning just the address.
func IPOnly(cidr string) string {
	addr, _, _ := strings.Cut(cidr, "/")
	return addr
}
