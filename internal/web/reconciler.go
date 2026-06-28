package web

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ggo-kea-dhcp/internal/config"
	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
)

// ReconcileMode controls how aggressively the reconciler rebuilds runtime state.
type ReconcileMode int

const (
	// ModeConverge brings runtime state to match the persisted lifecycle state
	// idempotently: no snapshots, no DB writes, and it never tears down working
	// NM connections wholesale (relies on per-connection delete-then-add). Used
	// on boot and for live settings convergence.
	ModeConverge ReconcileMode = iota
	// ModeApply is ModeConverge plus a full NM teardown first (so stale scopes
	// from a previous profile are removed). Snapshots are taken by the caller
	// before invoking this (see handleSetupApply), so rollback never depends on
	// querying the DB after a failed apply.
	ModeApply
)

const defaultOnboardingCIDR = "10.0.0.1/24"

// softAPWlanIP is the fixed address hostapd assigns to wlan0 in onboarding. Kept
// in sync with softAPWlanCIDR in internal/network/hostapd.go (top corner of the
// 172.16/12 RFC 1918 range, away from the operator subnets on eth0).
const softAPWlanIP = "172.31.255.1"

// reconcileWatchdog bounds how long a background reconcile may run before we log
// that it is still in flight. We cannot cancel it - the underlying nmcli/Kea
// calls are not context-aware - but a log line beats a silent hang.
const reconcileWatchdog = 60 * time.Second

// resumeApplyAttempts / resumeApplyBackoff bound how hard a boot-time resume of an
// interrupted apply retries before falling back to ONBOARDING, so a transient
// cold-boot error (Kea socket / eth0 not up yet) doesn't discard an applied profile.
// Vars (not consts) so tests can shrink the backoff.
var (
	resumeApplyAttempts = 5
	resumeApplyBackoff  = 2 * time.Second
)

// reconcileBusyMsg is shown when a mutating action is refused because an apply,
// switch, or reconcile already holds the guard.
const reconcileBusyMsg = "A configuration change is already in progress - try again in a moment."

// beginReconcile claims the single appliance-mutation guard shared by every path
// that rewrites kea-dhcp4.conf / the lifecycle state (apply, switch, settings,
// reset, pools, restore). It returns false when another such path is already
// running, so the caller can refuse instead of racing a second reconcile against
// the live config. On success the caller OWNS the guard and must release it -
// endReconcile for synchronous work, or hand it to scheduleReconcileHeld which
// releases it when the background reconcile finishes.
func (s *Server) beginReconcile() bool { return s.applying.CompareAndSwap(false, true) }

// endReconcile releases the guard claimed by beginReconcile.
func (s *Server) endReconcile() { s.applying.Store(false) }

// scheduleReconcileHeld runs a reconcile in the background after an optional delay
// (which lets an already-flushed interstitial reach the client before links drop),
// then releases the guard the caller MUST already hold (via beginReconcile). This
// is the single entry point for the fire-and-forget reconciles triggered by
// settings saves and resets - serialized against apply/switch by the shared guard.
func (s *Server) scheduleReconcileHeld(label string, delay time.Duration, mode ReconcileMode, profileID int) {
	go func() {
		defer s.endReconcile()
		if delay > 0 {
			time.Sleep(delay)
		}
		wd := time.AfterFunc(reconcileWatchdog, func() {
			log.Printf("[reconcile:%s] still running after %s", label, reconcileWatchdog)
		})
		err := s.ReconcileApplianceState(mode, profileID)
		wd.Stop()
		if err != nil {
			log.Printf("[reconcile:%s] reported: %v", label, err)
		}
	}()
}

// ReconcileApplianceState is the single authority that makes runtime network +
// Kea state match the persisted lifecycle state. targetProfileID==0 means "use
// the active profile" (only relevant in ACTIVE).
func (s *Server) ReconcileApplianceState(mode ReconcileMode, targetProfileID int) error {
	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	if state == "" {
		state = db.StateFactory
	}

	// A box found persisted in CONFIGURING during a converge (boot/settings - not
	// the apply goroutine's own ModeApply) had its apply interrupted. Complete it
	// rather than reconcile blindly (see resumeInterruptedApply).
	if interruptedMidApply(state, mode) {
		return s.resumeInterruptedApply(targetProfileID)
	}

	switch state {
	case db.StateActive, db.StateConfiguring:
		// ACTIVE and a live-apply CONFIGURING both serve the profile's scopes.
		return s.reconcileActive(mode, targetProfileID)
	default: // FACTORY and ONBOARDING share identical network state.
		return s.reconcileOnboarding(mode)
	}
}

// resumeInterruptedApply completes a profile apply that was interrupted (the box
// was found persisted in CONFIGURING at boot/converge, with no apply goroutine
// running). It brings the active profile fully up; on success it finalizes the
// ACTIVE state the apply goroutine never reached, and only on a *failed* reconcile
// does it fall back to ONBOARDING. This deliberately COMPLETES rather than
// discards - covering both a genuinely half-applied box and one whose apply
// succeeded but whose ACTIVE state-write was interrupted (reconcile is idempotent
// and re-validates the config, so finishing is safe).
func (s *Server) resumeInterruptedApply(profileID int) error {
	log.Printf("[reconcile] found %s at converge - completing the interrupted apply", db.StateConfiguring)
	// Retry with backoff before giving up: on a cold boot the Kea control socket or
	// eth0 link may not be up yet, and reconcileActive folds such transient errors in
	// with errors.Join. Reverting a profile that was actually applied back to
	// ONBOARDING on a transient boot hiccup would dump the operator to the SoftAP
	// mid-deployment, so we re-try (reconcile is idempotent) before falling back.
	var err error
	for attempt := 1; attempt <= resumeApplyAttempts; attempt++ {
		if err = s.reconcileActive(ModeConverge, profileID); err == nil {
			break
		}
		log.Printf("[reconcile] resume attempt %d/%d did not complete: %v", attempt, resumeApplyAttempts, err)
		if attempt < resumeApplyAttempts {
			time.Sleep(resumeApplyBackoff)
		}
	}
	if err != nil {
		log.Printf("[reconcile] could not complete interrupted apply after %d attempts (%v) - reverting to ONBOARDING", resumeApplyAttempts, err)
		_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding)
		return s.reconcileOnboarding(ModeConverge)
	}
	if e := s.sqlite.SetState(db.LifecycleStateKey, db.StateActive); e != nil {
		log.Printf("[reconcile] completed interrupted apply but failed to persist ACTIVE: %v", e)
	}
	// Drop any profile that persistProfile renamed aside as a rollback stash: a
	// crash between persistProfile and finishApply leaves one behind, and the
	// apply we just completed made the new profile authoritative.
	if e := s.sweepOrphanedStashes(); e != nil {
		log.Printf("[reconcile] failed to sweep orphaned apply stash: %v", e)
	}
	return nil
}

// sweepOrphanedStashes drops any rollback-stash profile (persistProfile renames a
// replaced same-named profile aside as "<name>.stash-<id>", always active = 0) that a
// crash between persistProfile and finishApply left behind. The active = 0 guard means
// it can never delete a live profile. Idempotent; excluded from the switcher too (see
// listProfiles). Returns the error for the caller to log.
func (s *Server) sweepOrphanedStashes() error {
	_, err := s.sqlite.Exec("DELETE FROM profiles WHERE active = 0 AND name GLOB '*.stash-[0-9]*'")
	return err
}

// interruptedMidApply reports whether the appliance was found mid-apply at boot:
// the persisted CONFIGURING marker during a converge (boot/settings) rather than
// the ModeApply call the apply goroutine itself makes.
func interruptedMidApply(state string, mode ReconcileMode) bool {
	return state == db.StateConfiguring && mode == ModeConverge
}

// reconcileOnboarding brings up the onboarding environment: eth0 management IP,
// wlan0 SoftAP, captive DNS, torn-down NAT, and the ungrouped dynamic Kea scope.
func (s *Server) reconcileOnboarding(mode ReconcileMode) error {
	var errs []error
	cidr := s.onboardingCIDR()
	ssid, pass := s.softAPSettings()

	if mode == ModeApply {
		_ = s.net.DeleteApplianceConnections()
	}

	if err := s.net.SetInterfaceStatic("eth0", cidr); err != nil {
		errs = append(errs, fmt.Errorf("eth0 static: %w", err))
	}
	// Onboarding ALWAYS raises the SoftAP: it is the operator's guaranteed way in when a
	// reset drops them here with no other access (an in-place "Edit Configuration" from
	// ACTIVE never reaches this path - it applies via reconcileActive, which tears the
	// SoftAP down). StartSoftAP flushes wlan0 first, so a prior uplink address can't linger
	// and shadow the SoftAP's own DHCP.
	_ = s.net.SetInterfaceManaged("wlan0", false)
	if err := s.net.StartSoftAP(ssid, pass); err != nil {
		errs = append(errs, fmt.Errorf("softap: %w", err))
	}

	// Leaving ACTIVE: stop the passive monitor and the active ARP prober (both run only
	// in ACTIVE). Beside s.dns.Stop()'s onboarding lifecycle; idempotent if nothing runs.
	if s.netmon != nil {
		s.netmon.Stop()
	}
	if s.arp != nil {
		s.arp.Stop()
	}
	if s.ggoscan != nil {
		s.ggoscan.Stop()
	}
	// Onboarding-only: passively sniff eth0 for tagged VLANs so the wizard's link badge can
	// tell the operator the switch port is a trunk. Best-effort (no CAP_NET_RAW -> inert).
	if s.trunkProbe != nil {
		s.trunkProbe.Start("eth0")
	}

	// Onboarding never routes - make sure no NAT state leaks in from a prior gig.
	_ = s.net.SetIPForwarding(false)
	_ = s.net.ApplyMasquerade("wlan0", false)
	_ = s.net.ClearPortForwards()

	// No captive DNS redirector and no DHCP gateway/DNS handout during onboarding: that
	// made connected PCs route their (non-existent) internet through the box and tripped
	// the OS captive-portal assistant into a self-signed-cert loop. Clients reach the box
	// on its own same-subnet address. wlanIP is still needed for the onboarding Kea scope.
	wlanIP := ""
	if _, err := net.InterfaceByName("wlan0"); err == nil {
		wlanIP = softAPWlanIP
	}
	s.dns.Stop() // idempotent: ensure no redirector lingers from a prior onboarding pass

	// Onboarding Kea config. Deliberately carries NO MariaDB backend (see
	// RenderOnboarding): eth0 DHCP must come up regardless of MariaDB state.
	cfgStr, _, err := kea.RenderOnboarding(kea.OnboardingInput{
		EthCIDR:       cidr,
		WlanIP:        wlanIP,
		KeaSecretPath: s.cfg.KeaSecretPath,
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("render onboarding: %w", err))
	} else if werr := s.writeAndReloadKea(cfgStr); werr != nil {
		errs = append(errs, werr)
	} else if mode == ModeApply {
		// A reset (ModeApply) must not inherit the prior job's leases: the memfile lease
		// store survives a config reload, so stale leases - and the learnable ports derived
		// from them - would otherwise persist. Wipe now that Kea is up with the onboarding
		// config. Best-effort: a wipe failure must not fail the reset. (A first onboarding
		// has no leases, so this is a harmless no-op there.)
		if werr := s.kea.WipeLeases(); werr != nil {
			log.Printf("[Reconcile] onboarding lease wipe failed: %v", werr)
		}
	}

	return errors.Join(errs...)
}

// reconcileActive brings up all served interfaces, renders+reloads the profile
// Kea config, and applies (or tears down) uplink NAT.
func (s *Server) reconcileActive(mode ReconcileMode, profileID int) error {
	var errs []error

	// Leaving onboarding: the trunk probe is an onboarding-only hint, and ACTIVE has the
	// full passive monitor for VLAN reality. (Its last-seen VLANs are snapshotted at apply.)
	if s.trunkProbe != nil {
		s.trunkProbe.Stop()
	}

	scopes, err := s.loadScopeConfigs(profileID)
	if err != nil {
		return fmt.Errorf("active reconcile: load scopes: %w", err)
	}
	if len(scopes) == 0 {
		return fmt.Errorf("active reconcile: no scopes for the active profile")
	}

	if mode == ModeApply {
		_ = s.net.DeleteApplianceConnections()
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
			if e := s.net.SetInterfaceStatic("eth0", staticCIDR); e != nil {
				errs = append(errs, fmt.Errorf("eth0 static: %w", e))
			}
		} else {
			if e := s.net.SetVlanStatic("eth0", sc.VlanID, staticCIDR); e != nil {
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
	boxUplinkEnabled, upSSID, upPass := s.uplinkSettings()
	hasUplink := boxUplinkEnabled && anyScopeUplink && upSSID != ""

	// Active mode: tear down onboarding-only services.
	_ = s.net.StopSoftAP()
	_ = s.net.SetInterfaceManaged("wlan0", true)
	s.dns.Stop()

	// Render + write + reload Kea from the scopes already loaded above (no second
	// DB load / JSON unmarshal).
	reloadOK := false
	cfgStr, _, rerr := s.renderKeaForScopes(scopes)
	if rerr != nil {
		errs = append(errs, fmt.Errorf("render profile: %w", rerr))
	} else if werr := s.writeAndReloadKea(cfgStr); werr != nil {
		errs = append(errs, werr)
	} else {
		reloadOK = true
	}

	if e := s.applyNAT(hasUplink); e != nil {
		errs = append(errs, e)
	}

	// WiFi uplink: (re)connect (slow, only when needed and not already up) using the
	// box-level credentials (one wlan0); or tear the connection down when nothing routes
	// through it (master off, or no scope toggled), so disabling the uplink in Settings
	// actually drops wlan0 - converge fully owns the uplink state.
	switch {
	case hasUplink && !s.net.IsWifiUplinkActive():
		go s.connectUplink(upSSID, upPass)
	case !hasUplink:
		_ = s.net.DisconnectWifiUplink()
	}

	// Now the new class guards are live, relocate any device sitting in the wrong pool
	// (e.g. a beltpack that earlier landed in a catch-all) into its own device-class
	// pool when that pool has room - by releasing the stale lease so it re-DHCPs.
	// Best-effort; gated on a successful reload so we never act against a config Kea
	// did not accept.
	if reloadOK {
		s.rebalanceLeases(scopes)
	}

	// Passive network-health monitoring AND the active ARP presence prober run only in
	// ACTIVE: this is their sole Start site, reached once the served interfaces are up.
	// Best-effort - both launch goroutines, never error, and so cannot affect the
	// reconcile outcome (errs above), keeping the core apply path isolated.
	s.startNetmon(scopes)
	s.startArpProber(scopes)
	s.startGgoScan(scopes)

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
func (s *Server) connectUplink(ssid, pwd string) {
	if e := s.net.SetWifiUplink(ssid, pwd); e != nil {
		log.Printf("Warning: WiFi uplink connect failed: %v", e)
		// Surface the failure the way Kea/MariaDB outages are (onBackendChange):
		// a SYSTEM audit event so it appears on the Audit Log and Diagnostics, not
		// just stderr. WARNING, not ERROR - DHCP still serves locally, only the
		// upstream is lost. The detail carries nmcli's reason (e.g. bad password /
		// SSID not found), so "the SSID or password is wrong" finally reaches the UI.
		// Debounced: only the down transition is logged, not every retry.
		if s.uplink.observe(false) {
			_ = s.sqlite.LogAudit("SYSTEM", "UPLINK_DOWN", ssid, "", e.Error(), "WARNING")
		}
		// Surface it to whatever page the operator has open NOW (not just the Audit
		// Log): the connect runs in a background goroutine, so the Settings save that
		// triggered it already returned "saved". The always-on #backend-alert banner
		// carries nmcli's reason so "the SSID or password is wrong" reaches the UI.
		s.health.setUplinkDown(true, "Wi-Fi uplink: "+e.Error())
		s.publishBackendAlert()
		return
	}
	if st, _ := s.sqlite.GetState(db.LifecycleStateKey); st != db.StateActive && st != db.StateConfiguring {
		log.Printf("[uplink] appliance left the active state (%s) during connect - tearing down stale uplink", st)
		_ = s.net.DisconnectWifiUplink()
		// Deliberate teardown (not a failure), so it is not audited - but mark the link
		// down so a genuine re-connect after the box returns to ACTIVE audits UPLINK_UP.
		s.uplink.observe(false)
		s.health.setUplinkDown(false, "") // not a failure - clear any prior alert
		s.publishBackendAlert()
		return
	}
	// Debounced: log UPLINK_UP only on an actual down->up (or first) transition, so a
	// re-saved unchanged uplink does not spam the Audit Log.
	if s.uplink.observe(true) {
		_ = s.sqlite.LogAudit("SYSTEM", "UPLINK_UP", ssid, "", "connected", "OK")
	}
	s.health.setUplinkDown(false, "") // connected - clear the banner
	s.publishBackendAlert()
}

// applyNAT enables masquerade + forwarding when any scope has an uplink, and
// fully tears it down otherwise. Idempotent (ApplyMasquerade flushes first).
func (s *Server) applyNAT(hasUplink bool) error {
	var errs []error
	if hasUplink {
		if e := s.net.SetIPForwarding(true); e != nil {
			errs = append(errs, fmt.Errorf("ip_forward on: %w", e))
		}
		if e := s.net.ApplyMasquerade("wlan0", true); e != nil {
			errs = append(errs, fmt.Errorf("masquerade on: %w", e))
		}
		_ = s.net.ClearPortForwards() // no port-forward model yet; keep clean
	} else {
		_ = s.net.SetIPForwarding(false)
		_ = s.net.ApplyMasquerade("wlan0", false)
		_ = s.net.ClearPortForwards()
	}
	return errors.Join(errs...)
}

// renderKeaForScopes renders the profile Kea config from already-loaded scopes
// (the caller loads them once and passes them in, avoiding a second DB read +
// JSON unmarshal on the boot/converge critical path).
func (s *Server) renderKeaForScopes(scopes []ScopeConfig) (string, []string, error) {
	if len(scopes) == 0 {
		return "", nil, fmt.Errorf("no scopes for profile")
	}

	host, user, pass, name := config.ParseMariaDSN(s.cfg.MariaDBDSN)
	in := kea.ProfileRenderInput{
		MariaDBHost:   host,
		MariaDBUser:   user,
		MariaDBPass:   pass,
		MariaDBName:   name,
		KeaSecretPath: s.cfg.KeaSecretPath,
		LeaseLifetime: s.leaseLifetime(),
	}
	g := s.globalDHCPOptions()
	in.GlobalDNS = g.DNS
	in.GlobalOptions = g.keaOptions()
	boxUplink, _, _ := s.uplinkSettings()
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

// snapshotKeaConf copies the current live Kea config into the snapshot directory
// and records it, returning the snapshot path for rollback. A missing live conf
// (first apply) is not an error and returns an empty path.
func (s *Server) snapshotKeaConf(reason string) (string, error) {
	live := filepath.Join(s.cfg.KeaConfDir, "kea-dhcp4.conf")
	data, err := os.ReadFile(live)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read live kea conf: %w", err)
	}
	if err := os.MkdirAll(s.cfg.SnapshotDir, 0700); err != nil {
		return "", fmt.Errorf("create snapshot dir: %w", err)
	}
	path := filepath.Join(s.cfg.SnapshotDir, fmt.Sprintf("kea-dhcp4.%d.conf", time.Now().UnixNano()))
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("write snapshot: %w", err)
	}
	_, _ = s.sqlite.Exec("INSERT INTO config_snapshots (reason, path) VALUES (?, ?)", reason, path)
	return path, nil
}

// writeAndReloadKea validates, writes the rendered config to the live path, and
// reloads Kea. Validation happens before the live file is touched so a bad
// render can't take Kea down on reload - this covers the boot/settings/reset
// converge paths that don't go through handleSetupApply's own pre-apply check.
func (s *Server) writeAndReloadKea(configStr string) error {
	if err := kea.TestConfig(configStr); err != nil {
		return fmt.Errorf("kea config validation failed: %w", err)
	}
	live := filepath.Join(s.cfg.KeaConfDir, "kea-dhcp4.conf")
	if err := os.WriteFile(live, []byte(configStr), 0660); err != nil {
		return fmt.Errorf("write kea conf: %w", err)
	}
	if err := s.kea.ReloadConfig(); err != nil {
		// If the control socket itself was unreachable (transport refused, not a
		// command-level rejection), Kea is running a config without the :8004 HTTP
		// socket - and config-reload can never recover that, because it needs :8004.
		// Restart Kea so it re-reads the file we just wrote (which always carries the
		// :8004 socket), then re-probe. Guarded by Installed() so a dev sandbox with
		// no Kea keeps the old fast-fail behaviour instead of waiting on a no-op
		// restart.
		if !s.kea.Reachable() && kea.Installed() {
			log.Printf("[kea] control socket unreachable on reload - restarting %s to load the on-disk config", keaServiceName)
			if rerr := s.net.RestartService(keaServiceName); rerr != nil {
				return fmt.Errorf("reload kea: socket unreachable and restart failed: %v (reload: %w)", rerr, err)
			}
			if perr := s.waitKeaReachable(5, time.Second); perr != nil {
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

// waitKeaReachable polls Kea's control socket until it answers or the attempts run
// out, returning the last probe error.
func (s *Server) waitKeaReachable(attempts int, delay time.Duration) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = s.kea.Ping(); err == nil {
			return nil
		}
		time.Sleep(delay)
	}
	return err
}

// --- app_state-backed settings with defaults ---

func (s *Server) onboardingCIDR() string {
	if v, _ := s.sqlite.GetState("onboarding_ip"); v != "" {
		return v
	}
	return defaultOnboardingCIDR
}

func (s *Server) softAPSettings() (ssid, pass string) {
	ssid, _ = s.sqlite.GetState("softap_ssid")
	if ssid == "" {
		ssid = "GGO-DHCP-Onboarding"
	}
	pass, _ = s.sqlite.GetState("softap_pass")
	return ssid, pass
}

// uplinkSettings returns the box-level WiFi uplink config (one wlan0): the master
// enable plus the SSID/password handed to NetworkManager, from app_state. WHICH scopes
// route through the uplink is the per-scope toggle (ScopeConfig.Uplink.Enabled); this
// master enable governs the whole uplink - off means no scope routes, full stop.
func (s *Server) uplinkSettings() (enabled bool, ssid, pass string) {
	e, _ := s.sqlite.GetState("uplink_enabled")
	ssid, _ = s.sqlite.GetState("uplink_ssid")
	pass, _ = s.sqlite.GetState("uplink_pass")
	return e == "1", ssid, pass
}

// migrateUplinkToBoxLevel seeds the box-level uplink app_state keys from a legacy
// per-scope uplink_json once (the pre-box-level model), so an upgraded box keeps its
// configured uplink. No-op once a box-level key exists.
func (s *Server) migrateUplinkToBoxLevel() {
	if v, _ := s.sqlite.GetState("uplink_ssid"); v != "" {
		return
	}
	if v, _ := s.sqlite.GetState("uplink_enabled"); v != "" {
		return
	}
	_, cfg, ok := s.activeProfileUplink()
	if !ok || cfg.SSID == "" {
		return
	}
	en := "0"
	if cfg.Enabled {
		en = "1"
	}
	if err := s.sqlite.SetStates(map[string]string{"uplink_ssid": cfg.SSID, "uplink_pass": cfg.Password, "uplink_enabled": en}); err != nil {
		log.Printf("[migrate] seed box-level uplink: %v", err)
		return
	}
	log.Printf("[migrate] seeded box-level WiFi uplink from legacy per-scope config")
}

// leaseLifetime returns the active-profile DHCP lease lifetime in seconds: the operator's
// saved Settings value (app_state "lease_lifetime") when set and valid, else the
// --lease-lifetime flag default. Settings is the single source of truth; the flag is only
// the fallback.
func (s *Server) leaseLifetime() int {
	if v, _ := s.sqlite.GetState("lease_lifetime"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return s.cfg.LeaseLifetime
}

// ipOnly strips a /mask suffix, returning just the address.
func ipOnly(cidr string) string {
	addr, _, _ := strings.Cut(cidr, "/")
	return addr
}
