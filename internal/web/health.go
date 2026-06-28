package web

import (
	"strings"
	"sync"
	"time"

	"ggo-kea-dhcp/internal/preflight"
	"ggo-kea-dhcp/internal/web/views"
)

// backendDownThreshold is the number of consecutive failed samples before a
// backend is declared DOWN. It debounces boot races (Kea not yet started by the
// reconciler) and transient blips; recovery (UP) is reported immediately.
const backendDownThreshold = 2

// backendProbeInterval is how often MariaDB reachability is probed. Kea health is
// observed by the metrics sampler on its own cadence (no separate probe).
const backendProbeInterval = 30 * time.Second

// backendTracker is the debounced up/down state of one runtime backend.
type backendTracker struct {
	healthy bool
	detail  string
	fails   int
}

// observe records one sample and reports whether the up/down state changed and
// the new state. DOWN is debounced by backendDownThreshold; UP is immediate.
func (t *backendTracker) observe(ok bool, detail string) (changed, healthy bool) {
	t.detail = detail
	if ok {
		t.fails = 0
		if !t.healthy {
			t.healthy = true
			return true, true
		}
		return false, true
	}
	t.fails++
	if t.healthy && t.fails >= backendDownThreshold {
		t.healthy = false
		return true, false
	}
	return false, t.healthy
}

// backendHealth tracks the live reachability of Kea and MariaDB so the UI can warn
// on every page and each transition gets exactly one audit row. Both start
// optimistic (healthy): a backend up from boot logs no transition; one that is
// down trips to DOWN after backendDownThreshold samples.
type backendHealth struct {
	mu      sync.Mutex
	kea     backendTracker
	mariadb backendTracker

	// uplink is observed on demand by connectUplink (no periodic probe), so it is a
	// plain latched state rather than a debounced tracker - the first failure shows
	// immediately, and it clears on a successful (re)connect or a deliberate disable.
	uplinkDown   bool
	uplinkDetail string
}

func newBackendHealth() *backendHealth {
	return &backendHealth{
		kea:     backendTracker{healthy: true},
		mariadb: backendTracker{healthy: true},
	}
}

// setUplinkDown latches the Wi-Fi uplink alert state. detail carries the nmcli reason
// (bad password / SSID not found) when down.
func (h *backendHealth) setUplinkDown(down bool, detail string) {
	h.mu.Lock()
	h.uplinkDown = down
	h.uplinkDetail = detail
	h.mu.Unlock()
}

func (h *backendHealth) observeKea(ok bool, detail string) (changed, healthy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.kea.observe(ok, detail)
}

func (h *backendHealth) observeMariaDB(ok bool, detail string) (changed, healthy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mariadb.observe(ok, detail)
}

// alertRows builds the banner rows for the current state: Kea down is an error
// (DHCP stops entirely); MariaDB down is a warning (dynamic leases keep serving,
// only reservations and port pinning are unavailable). Empty when both are up.
func (h *backendHealth) alertRows() []views.AlertRow {
	h.mu.Lock()
	keaOK, mariaOK := h.kea.healthy, h.mariadb.healthy
	upDown, upDetail := h.uplinkDown, h.uplinkDetail
	h.mu.Unlock()

	var rows []views.AlertRow
	if !keaOK {
		rows = append(rows, views.AlertRow{
			Severity: "err",
			Title:    "DHCP Server Offline",
			Detail:   "Kea is not answering on its control socket - new DHCP requests may not be served. Check: systemctl status kea-dhcp4",
		})
	}
	if !mariaOK {
		rows = append(rows, views.AlertRow{
			Severity: "warn",
			Title:    "Reservation Database Offline",
			Detail:   "Dynamic leases continue to serve; host reservations and port pinning are unavailable until MariaDB returns.",
		})
	}
	if upDown {
		rows = append(rows, views.AlertRow{
			Severity: "warn",
			Title:    "Wi-Fi Uplink Offline",
			Detail:   upDetail, // the nmcli reason (empty -> the title alone is enough)
		})
	}
	return rows
}

// preflightAlertRows returns a single summary banner row when the last preflight
// snapshot has any Warn/Fail check, so a degraded prerequisite (e.g. missing
// CAP_NET_RAW -> the network monitor is silently disabled) is visible on every
// page instead of only on the Diagnostics tab. Empty when all checks pass.
// Severity follows the worst check (Fail -> err, Warn -> warn); one row, not one
// per check, so a multiply-degraded box does not stack banners. Preflight inputs
// (caps, tools, hooks, version) are static at runtime, so the boot snapshot held
// in s.preflight is accurate without extra polling.
func (s *Server) preflightAlertRows() []views.AlertRow {
	pf := s.Preflight()
	worst := pf.Worst()
	if worst == preflight.OK {
		return nil
	}
	var names []string
	for _, c := range pf {
		if c.Status != preflight.OK {
			names = append(names, c.Name)
		}
	}
	sev, title := "warn", "Degraded Prerequisites"
	if worst == preflight.Fail {
		sev, title = "err", "Prerequisite Check Failed"
	}
	return []views.AlertRow{{
		Severity: sev,
		Title:    title,
		Detail:   "Affected: " + strings.Join(names, ", ") + ". Open the Diagnostics tab for detail.",
	}}
}

// backendAlertRows is the full always-on banner set: live backend reachability
// (Kea/MariaDB/uplink) plus any degraded boot-time prerequisite. Used for both the
// first paint and the live #backend-alert pushes so the two never diverge.
func (s *Server) backendAlertRows() []views.AlertRow {
	var rows []views.AlertRow
	if s.health != nil {
		rows = s.health.alertRows()
	}
	return append(rows, s.preflightAlertRows()...)
}

// startBackendHealthProbe launches the MariaDB reachability probe. The reconnect
// itself is automatic (database/sql pooling + ConnMaxLifetime); this probe is what
// flips the UI/audit state back to healthy once MariaDB returns - no restart needed.
func (s *Server) startBackendHealthProbe() {
	go func() {
		s.probeMariaDB() // establish baseline promptly
		t := time.NewTicker(backendProbeInterval)
		defer t.Stop()
		for range t.C {
			s.probeMariaDB()
		}
	}()
}

// probeMariaDB pings MariaDB and records the result on the health aggregator,
// auditing + pushing the banner on a transition.
func (s *Server) probeMariaDB() {
	// No MariaDB handle means it was never configured (empty/invalid DSN) - a
	// documented degraded mode, not a runtime outage. Don't raise a "Reservation
	// Database Offline" banner that could never clear; the pinning/reservation
	// pages already show an inline "not connected" notice. Only a configured
	// backend that goes unreachable is reported.
	if s.mariadb == nil {
		return
	}
	ok, detail := false, ""
	if err := s.mariadb.Ping(); err != nil {
		detail = err.Error()
	} else {
		ok, detail = true, "connected"
	}
	if changed, healthy := s.health.observeMariaDB(ok, detail); changed {
		s.onBackendChange("MARIADB", healthy, detail)
	}
}

// onBackendChange records a backend up/down transition in the audit log and pushes
// the live banner to every connected page immediately (not just on the next tick).
func (s *Server) onBackendChange(backend string, healthy bool, detail string) {
	var action, result string
	if healthy {
		action, result = backend+"_UP", "OK"
	} else {
		action = backend + "_DOWN"
		if backend == "KEA" {
			result = "ERROR" // DHCP stops entirely
		} else {
			result = "WARNING" // degraded: dynamic leases still serve
		}
	}
	_ = s.sqlite.LogAudit("SYSTEM", action, backend, "", detail, result)
	s.publishBackendAlert()
	// Kea going down is the one "DHCP just stopped" event worth an instant nudge on
	// top of the persistent strip - push a one-shot toast on its down/up edge. (The
	// strip alone covers the standing condition for warnings like MariaDB/uplink.)
	if backend == "KEA" {
		s.live.publishIfChanged("kea-toast", renderFragment(views.KeaToastSlot(!healthy)))
	}
}

// publishBackendAlert pushes the always-on #backend-alert strip (above the page h1)
// when backend health changes (Kea/MariaDB/uplink up or down). Event-driven so a
// transition shows immediately, not on the next live tick; the change-only gate
// suppresses an identical re-push.
func (s *Server) publishBackendAlert() {
	if s.health == nil {
		return
	}
	s.live.publishIfChanged("backend-alert", renderFragment(views.BackendAlert(s.backendAlertRows())))
}
