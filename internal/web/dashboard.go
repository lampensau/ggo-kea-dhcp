package web

import (
	"context"
	"encoding/json"
	"fmt"
	"ggo-kea-dhcp/internal/appliance"
	"log"
	"net/http"
	"sort"
	"strings"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/starfederation/datastar-go/datastar"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.renderTempl(w, r, views.Dashboard(s.buildDashboardView(r.Context(), s.pageData(w, r, "Dashboard"))))
}

// buildDashboardView gathers the appliance state (active profile, scopes, leases)
// and assembles the dashboard view: a compact summary, three at-a-glance tiles,
// and the address-pool table. It is shared by the page handler and the SSE ticker
// (live.go), so first paint and every live fragment derive from the same
// computation and cannot drift. pd is the shell context (empty for the ticker).
func (s *Server) buildDashboardView(ctx context.Context, pd views.PageData) views.DashboardView {
	// Read through the shared cache: the page render then primes leaseSrc so the SSE
	// connect snapshot that follows 0-3s later rides it instead of re-polling Kea.
	leases, keaErr := s.getLeases(ctx, leaseSrcTTL)
	if keaErr != nil {
		log.Printf("[Dashboard] Kea lease query failed: %v", keaErr)
	}
	return s.buildDashboardViewWithLeases(ctx, pd, leases)
}

// buildDashboardViewWithLeases builds the dashboard view from an already-fetched
// lease set, so the live ticker can fetch leases once (the only unavoidable poll),
// decide nothing changed, and skip this work entirely. It collects the netmon
// snapshot once and delegates to buildDashboardViewWith.
func (s *Server) buildDashboardViewWithLeases(ctx context.Context, pd views.PageData, leases []kea.ActiveLease) views.DashboardView {
	return s.buildDashboardViewWith(ctx, pd, leases, s.collectNetSnapshot(), true, s.fetchHWReservationMap(ctx))
}

// buildDashboardViewWith builds the dashboard view from an already-fetched lease
// set AND an already-collected netmon snapshot, so a live broadcast can share one
// SnapshotAll across this view and the lease table (unifiedLeaseRowsFrom).
// withPinning gates the MariaDB pinning fetch: a metrics-only live tick passes
// false so it refreshes the periodic-cheap regions (tiles, net-health, activity)
// without the pinning/reservation round-trips - those regions change only on a
// lease change or an explicit pin op, both of which build the full view.
func (s *Server) buildDashboardViewWith(ctx context.Context, pd views.PageData, leases []kea.ActiveLease, ns netSnapshotData, withPinning bool, res map[string]db.HostReservation) views.DashboardView {
	var profileID int
	var profileName string
	if err := s.sqlite.QueryRow("SELECT id, name FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID, &profileName); err != nil {
		// No active profile (e.g. freshly out of onboarding).
		profileName = "No active profile"
	}

	dbScopes, err := s.loadScopeConfigs(profileID)
	if err != nil {
		log.Printf("[Dashboard] load scopes: %v", err)
	}

	var pools []views.PoolRow
	var activeIfaces []string
	uplinkActive := false
	parsed := parseLeases(leases) // once per build - poolDataForScope runs per scope
	for _, ds := range dbScopes {
		if ds.VlanID == 0 {
			activeIfaces = append(activeIfaces, "eth0")
		} else {
			activeIfaces = append(activeIfaces, fmt.Sprintf("eth0.%d", ds.VlanID))
		}
		if ds.Uplink.Enabled {
			uplinkActive = true
		}
		pools = append(pools, poolDataForScope(ds, parsed)...)
	}

	ifacesLabel := strings.Join(activeIfaces, ", ")
	if ifacesLabel == "" {
		ifacesLabel = "eth0"
	}

	// Label each Network Health sub-card with its scope's friendly name (the netmon
	// snapshot only knows the interface). A synthesized raw-eth0 trunk monitor has no
	// scope -> stays name-less and shows the interface alone.
	applyScopeNames(ns.Signals.Health.Interfaces, dbScopes)

	sortPoolsByPressure(pools)

	var profiles []views.ProfileOption
	if pd.Authenticated {
		profiles = s.listProfiles()
	}

	// One MariaDB fetch feeds both the dashboard pinnings card (#pinnings) and the
	// /pinning page live regions (#pinned-body / #learnable-body). Skipped on a
	// metrics-only refresh (withPinning=false) to avoid the round-trip.
	var pinned, learnable []views.PortRow
	if withPinning {
		pinned, learnable = s.fetchPinningSplit(ctx, leases)
	}
	sig := ns.Signals

	// "Active leases" must mean currently-held: drop leases Kea still returns but
	// that have lapsed (expired-not-yet-reclaimed) or are declined/released, so the
	// summary card and its count don't list expired leases as active. The full
	// /leases page keeps showing everything.
	// Dedupe a device that moved ports (a stale lease lingering under its old
	// flex-id alongside the fresh one) so the card, the count, and the tile all agree
	// with the /leases page and the live leases-body, which dedupe the same way.
	active := dedupeStaleLeases(activeLeases(leases))

	// Recent-leases card: top active leases plus awaiting-renewal hosts (online but
	// unleased after a purge - the card must not go empty while devices are up),
	// tagged with passive online/offline. Awaiting hosts covered by a hw-address
	// reservation (res, prefetched by the caller and shared with the lease-table
	// build) are dropped so the card agrees with /leases, where the reservation
	// row's MAC suppresses the awaiting row. The metrics-only path passes nil - it
	// never broadcasts this card, so its unfiltered build is never shown.
	//
	// The card shows only devices that are actually there: presence is marked BEFORE
	// the top-8 cut and prober-confirmed-offline rows are dropped (a powered-off
	// device's lease keeps counting down on /leases, which shows everything; the
	// dashboard is the live-room view). Unknown presence (prober unavailable) is
	// kept - "can't tell" must not empty the card.
	recent := appendAwaitingRows(buildLeaseRows(active), filterAwaitingByMAC(ns.Awaiting, res))
	s.markLeasePresenceWith(ns.Live, ns.Available, recent)
	recent = dropOfflineRows(recent)
	sort.SliceStable(recent, func(i, j int) bool { return leaseIPKey(recent[i].IPAddress) < leaseIPKey(recent[j].IPAddress) })
	recent = topLeases(recent, 8)
	s.overlayGgoNamesWith(recent, ns.GgoNames)
	sanitizeLeaseHostnames(recent)

	return views.DashboardView{
		Page:         pd,
		ProfileName:  profileName,
		Preset:       dashboardPresetLabel(dbScopes),
		Interface:    ifacesLabel,
		TotalScopes:  len(dbScopes),
		LeaseCount:   len(active),
		UplinkActive: uplinkActive,
		Pools:        pools,
		Profiles:     profiles,
		NetHealth:    sig.Health,
		LLDP:         sig.LLDP,
		PTP:          sig.PTP,
		Stats:        buildStatTiles(len(active), pools, s.metrics.snapshot(), sig.PTP),
		Activity:     s.fetchRecentActivity(8),
		RecentLeases: recent,
		CanReserve:   s.mariadb != nil,
		Pinned:       pinned,
		Learnable:    learnable,
	}
}

// sortPoolsByPressure orders pools most-utilized first so the in-use pools sit at
// the top of the table and the always-empty ones fall to the bottom - surfacing
// what matters without hiding anything. Stable, in place.
func sortPoolsByPressure(pools []views.PoolRow) {
	sort.SliceStable(pools, func(i, j int) bool {
		if pools[i].Percent != pools[j].Percent {
			return pools[i].Percent > pools[j].Percent
		}
		return pools[i].Allocated > pools[j].Allocated
	})
}

// dashboardPresetLabel renders the human label for the active profile's preset
// mix. Pure, so it is unit-testable.
func dashboardPresetLabel(scopes []ScopeConfig) string {
	switch {
	case len(scopes) == 0:
		return "None"
	case len(scopes) == 1:
		return appliance.PresetLabel(scopes[0].Preset)
	default:
		return "Multi-VLAN Trunk"
	}
}

// poolDataForScope derives the read-only dashboard pool rows for one scope from
// its Plan, reusing buildPoolPlanView (the /pools computation) so the dashboard
// table and the editor share one source of ranges + utilization and cannot drift.
// Every scope carries a Plan (loadScopeConfigs seeds legacy rows), so this is the
// single occupancy path. Reserve entries are not DHCP pools, so they are omitted
// from the table; a malformed CIDR yields no rows.
func poolDataForScope(sc ScopeConfig, leases []parsedLease) []views.PoolRow {
	pv := buildPoolPlanView(sc, leases, true, planMode(sc.Plan))
	var data []views.PoolRow
	for _, r := range pv.Rows {
		if r.Reserve {
			continue
		}
		data = append(data, views.PoolRow{
			ClassName: r.Key,
			Label:     r.Name,
			IPRange:   r.Range,
			Allocated: r.Used,
			Capacity:  r.Capacity,
			Percent:   r.Percent,
		})
	}
	return data
}

func (s *Server) handleLeases(w http.ResponseWriter, r *http.Request) {
	// Read through the shared cache (see buildDashboardView) so the connect snapshot
	// that follows this page render does not issue a second lease poll.
	leases, err := s.getLeases(r.Context(), leaseSrcTTL)
	if err != nil {
		log.Printf("Kea API lease query failed: %v", err)
		s.renderTempl(w, r, views.Leases(views.LeasesView{
			Page:  s.pageData(w, r, "Leases"),
			Error: fmt.Sprintf("Failed to query active leases from Kea: %v", err),
		}))
		return
	}
	s.renderTempl(w, r, views.Leases(views.LeasesView{
		Page:       s.pageData(w, r, "Leases"),
		Leases:     s.unifiedLeaseRows(r.Context(), leases),
		CanReserve: s.mariadb != nil,
	}))
}

// filterLeases narrows the lease rows by a case-insensitive substring across the
// scannable columns.
func filterLeases(rows []views.LeaseRow, query string) []views.LeaseRow {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return rows
	}
	var out []views.LeaseRow
	for _, row := range rows {
		label := views.ClassDisplay(row.Class).Label
		if strings.Contains(strings.ToLower(row.IPAddress), query) ||
			strings.Contains(strings.ToLower(row.HWAddress), query) ||
			strings.Contains(strings.ToLower(row.Hostname), query) ||
			strings.Contains(strings.ToLower(row.Class), query) ||
			strings.Contains(strings.ToLower(label), query) {
			out = append(out, row)
		}
	}
	return out
}

func (s *Server) handleLeasesSearch(w http.ResponseWriter, r *http.Request) {
	// Datastar sends the bound signal (the search box) in the request; read it
	// via the SDK rather than a query param.
	var sig struct {
		Search string `json:"search"`
	}
	_ = datastar.ReadSignals(r, &sig)

	// Read-through: the search box filters a display snapshot - a debounced
	// keystroke must not cost a Kea round-trip when the ticker refreshed the
	// set moments ago.
	leases, err := s.getLeases(r.Context(), leaseSrcTTL)
	if err != nil {
		// Surface the real error rather than fabricate leases when Kea is down.
		log.Printf("Kea API lease query failed: %v", err)
		toast(datastar.NewSSE(w, r), fmt.Sprintf("Failed to query leases: %v", err), "error")
		return
	}

	filtered := filterLeases(s.unifiedLeaseRows(r.Context(), leases), sig.Search)
	sse := datastar.NewSSE(w, r)
	_ = sse.PatchElementTempl(views.LeasesBody(filtered, s.mariadb != nil))
}

func (s *Server) handleLeaseRelease(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	log.Printf("[Leases] Manually releasing lease for %s...", logSafe(ip))

	sse := datastar.NewSSE(w, r)
	if err := s.kea.DeleteLease(r.Context(), ip); err != nil {
		toast(sse, "Failed to release "+ip+": "+err.Error(), "error")
		return
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "LEASE_RELEASE", ip, "", "", "SUCCESS")

	// Re-render the lease table and confirm. The live channel also refreshes the
	// list, but patching here makes the release feel immediate. On a re-fetch
	// error leave the table untouched: repainting from a failed query would show
	// an empty table under the green toast, indistinguishable from a real wipe.
	if leases, err := s.kea.GetLeases(r.Context(), defaultLeasePageSize); err != nil {
		log.Printf("[Leases] post-release refresh failed (table left as-is): %v", err)
	} else {
		_ = sse.PatchElementTempl(views.LeasesBody(s.unifiedLeaseRows(r.Context(), leases), s.mariadb != nil))
	}
	toast(sse, "Released lease for "+ip, "success")

	// Release completes over SSE (no page reload), so the flash-context auto-open path
	// can't fire here. If the released device is a Green-GO client online now, open the
	// reboot-to-apply dialog directly via a one-shot ExecuteScript that calls the page's
	// opener (the dialog + opener are mounted on /leases). ExecuteScript self-removes the
	// script node after it runs, so repeated releases don't accumulate dead nodes. The
	// device is still physically at ip - releasing only drops the Kea lease - so it can
	// be reached and rebooted to re-request DHCP immediately. The MAC rides along as the
	// freshness anchor the reboot handler matches against.
	if dev, ok := s.rebootOfferForIP(ip); ok {
		rebootExecScript(sse, dev)
	}
}

// rebootExecScript opens the reboot-to-apply dialog on the submitting page over
// SSE (the live equivalent of setFlashDevice's reload-and-auto-open). The
// `ggoRebootOpen&&` guard makes it a no-op on a page without the opener mounted
// (e.g. a reserve submitted from the dashboard), so callers can always attempt
// it. ExecuteScript self-removes the node, so repeated ops don't pile up.
func rebootExecScript(sse *datastar.ServerSentEventGenerator, dev FlashDevice) {
	ipArg, _ := json.Marshal(dev.IP)
	nameArg, _ := json.Marshal(dev.Name)
	macArg, _ := json.Marshal(dev.MAC)
	_ = sse.ExecuteScript(
		"window.ggoRebootOpen&&window.ggoRebootOpen(" + string(ipArg) + "," + string(nameArg) + "," + string(macArg) + ")")
}
