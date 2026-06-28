package web

import (
	"context"
	"hash/fnv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/a-h/templ"
	"github.com/starfederation/datastar-go/datastar"
)

// liveTickInterval is how often Kea-derived live regions are re-polled while at
// least one operator is watching. Kea lease changes have no push event, so the
// ticker polls; publishIfChanged keeps an idle network silent (DESIGN §9).
const liveTickInterval = 4 * time.Second

// liveHub is a tiny in-process Server-Sent-Events broadcaster. A single operator
// means ~1 connected client, but it supports N. Publishers render a fragment for
// a stable DOM region (e.g. "state-badge") and call publish*; every subscriber
// writes it to its /sse/live stream, where Datastar outer-morphs it into the
// matching element by id. The same templ partial renders both first paint and
// the live fragment, so they cannot drift.
//
// "Change-only push" lives here: publishIfChanged hashes the fragment per region
// and broadcasts only when it differs from the last value sent for that region.
// The ticker further gates on a lease-set signature (markChanged) before it even
// renders, so an idle connected client costs only one lease poll + a hash per
// tick - never a wasted scope load or templ render.
type liveHub struct {
	mu       sync.Mutex
	subs     map[chan string]string // client channel -> the page path it is viewing
	lastHash map[string]uint64
	lastFrag map[string]string // region -> last fragment broadcast (for cheap re-sync)
}

func newLiveHub() *liveHub {
	return &liveHub{
		subs:     make(map[chan string]string),
		lastHash: make(map[string]uint64),
		lastFrag: make(map[string]string),
	}
}

// subscribe registers a new client (viewing page) and returns its event channel.
// The page scopes which regions it receives (regionOnPage), so a patch is never
// sent to a client whose DOM lacks the target - which Datastar v1 logs as a
// PatchElementsNoTargetsFound error. The buffer absorbs brief write stalls; a full
// channel drops the update (the next push, or a reconnect, re-syncs).
func (h *liveHub) subscribe(page string) chan string {
	ch := make(chan string, 16)
	h.mu.Lock()
	h.subs[ch] = page
	h.mu.Unlock()
	return ch
}

func (h *liveHub) unsubscribe(ch chan string) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// clientCount reports the number of connected subscribers. The refresh ticker
// uses this to stay idle while nobody is watching.
func (h *liveHub) clientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// publish broadcasts a fragment to every subscriber unconditionally (no per-page
// scoping). Used by tests; production paths go through publishIfChanged with a
// region so the patch is scoped to the pages that actually contain it.
func (h *liveHub) publish(fragment string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- fragment:
		default:
		}
	}
}

// publishIfChanged broadcasts fragment only if it differs from the last fragment
// sent for region. It reports whether a broadcast happened (used by tests and to
// keep the ticker quiet). region is the hash key, not part of the payload - the
// fragment's own element id is what Datastar targets.
func (h *liveHub) publishIfChanged(region, fragment string) bool {
	sum := fnv64(fragment)
	h.mu.Lock()
	defer h.mu.Unlock()
	if prev, ok := h.lastHash[region]; ok && prev == sum {
		return false
	}
	h.lastHash[region] = sum
	h.lastFrag[region] = fragment
	h.broadcastLocked(region, fragment)
	return true
}

// markChanged reports whether sig differs from the last value stored under key,
// updating the stored value. Unlike publishIfChanged it broadcasts nothing - it
// gates expensive work (skip re-rendering the dashboard when the lease set is
// unchanged) without first rendering a fragment to hash. key shares the lastHash
// namespace, so use a key distinct from any region id (e.g. "ticker-leases").
func (h *liveHub) markChanged(key string, sig uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if prev, ok := h.lastHash[key]; ok && prev == sig {
		return false
	}
	h.lastHash[key] = sig
	return true
}

// rebroadcastLast re-sends the LAST fragment broadcast for region to every matching
// subscriber, UNCONDITIONALLY (bypassing the change-only gate). A periodic re-sync uses
// it so a client whose view drifted stale - a push dropped on a full channel, or a
// snapshot taken before a device was first captured - reconciles even when the global
// lease/presence state is otherwise stable. The change-only gate alone offers such a
// client no "next push" to recover from, which is why the dots froze on /leases until a
// full reload. It re-sends the cached fragment rather than re-rendering, so the recovery
// costs no view build or MariaDB round-trip; the cache is kept current by the real render
// path (presence transitions re-render via the presence-folded lease signature). A no-op
// until that region has been broadcast at least once.
func (h *liveHub) rebroadcastLast(region string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if frag, ok := h.lastFrag[region]; ok {
		h.broadcastLocked(region, frag)
	}
}

// broadcastLocked fans a region's fragment out only to subscribers whose page
// contains that region's element, so a client never receives a patch for a DOM id
// it doesn't have (which Datastar logs as PatchElementsNoTargetsFound). Caller
// holds h.mu.
func (h *liveHub) broadcastLocked(region, fragment string) {
	for ch, page := range h.subs {
		if !regionOnPage(region, page) {
			continue
		}
		select {
		case ch <- fragment:
		default: // slow consumer: drop; reconnect/next push re-syncs
		}
	}
}

// regionOnPage reports whether a live region's element exists on the given page,
// so the hub only pushes patches a page can actually apply. state-badge/link-status
// live in the shell header (every authenticated page); the rest are page-specific.
// An empty page (no Referer) falls back to "send everything" so live updates are
// never silently dropped; a page with no live regions of its own (audit, settings,
// pools, reset) receives only the shell regions.
func regionOnPage(region, page string) bool {
	if region == "state-badge" || region == "sys-health" || region == "backend-alert" || region == "kea-toast" {
		return true // these live in the shell on every authenticated page
	}
	switch page {
	case "", "/":
		return true // unknown/root referer: don't risk dropping updates
	case "/dashboard":
		switch region {
		case "dash-tiles", "dash-lldp", "pool-table", "pool-rollup", "recent-leases", "activity-feed",
			"net-health", "net-health-rollup", "pinnings", "pinnings-rollup":
			return true
		}
	case "/leases":
		return region == "leases-body"
	case "/pinning":
		switch region {
		case "pinned-body", "learnable-body", "pinned-head", "learnable-head":
			return true
		}
	case "/setup":
		return region == "link-status" // the cable/link badge only exists in the wizard
	}
	return false
}

// refererPath extracts the path of the page that opened the SSE stream (Datastar
// streams over fetch, which sends a same-origin Referer). "" when absent.
func refererPath(r *http.Request) string {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return ""
	}
	if u, err := url.Parse(ref); err == nil {
		return u.Path
	}
	return ""
}

func fnv64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// startLiveTicker launches the background poll loop that keeps the dashboard's
// Kea-derived regions live. It runs only while a client is connected and pushes
// only changed regions, so an idle appliance costs nothing.
func (s *Server) startLiveTicker() {
	go func() {
		t := time.NewTicker(liveTickInterval)
		defer t.Stop()
		for range t.C {
			if s.live.clientCount() == 0 {
				continue
			}
			s.tickDashboard()
		}
	}()
}

// tickDashboard is the ticker's poll. The Kea lease query is the only unavoidable
// cost; when the lease set is unchanged since the last tick it skips the scope
// load and both templ renders entirely (an idle connected client costs one lease
// poll + a hash per tick, not a full re-render). Lifecycle/profile changes publish
// via publishDashboard (event-driven), so this only needs to watch the leases.
func (s *Server) tickDashboard() {
	leases, err := s.kea.GetLeases(1000)
	if err != nil {
		return // can't tell if anything changed; next tick retries
	}
	// Render when EITHER the lease set OR the sampled metrics changed - both
	// markChanged calls must run (no short-circuit) so both signatures advance.
	// Without the metrics check the stat-tile sparklines would freeze between
	// lease changes (the sampler pushes a new point every 12s).
	// Fold host-liveness into the lease signature so an online/offline transition of a
	// leased device - which does NOT change the lease set itself - still re-broadcasts the
	// lease rows. Without this the leases-body / recent-leases presence dots only refresh
	// when a lease is added or removed (or the page is fully reloaded). Per-region hashing
	// still suppresses any fragment whose rendered HTML did not actually change.
	reachable, _ := s.presenceByIP()
	leasesChanged := s.live.markChanged("ticker-leases", leasesSignature(leases)^presenceSignature(leases, reachable)^expirySignature(leases))
	metricsChanged := s.live.markChanged("ticker-metrics", s.metrics.signature())
	switch {
	case leasesChanged:
		// A lease change rebuilds every region (the full set includes the periodic
		// ones, so tiles/net-health/activity still refresh on this path).
		s.publishDashboardWithLeases(leases)
	case metricsChanged:
		// Metrics tick (every 12s): refresh the periodic-cheap regions, and - when a
		// client is connected - force-resync the lease-row regions so their presence dots
		// reconcile even if an earlier push was dropped or the lease/presence state has
		// stopped changing (the change-only gate would otherwise leave the dots frozen
		// until a full reload). Skipped entirely with no viewers, so an idle box pays
		// nothing.
		if s.live.clientCount() > 0 {
			s.publishMetricsTick(leases)
		}
	}
}

// publishMetricsTick refreshes the live regions on the 12s metrics tick. The
// periodic-cheap regions (tiles, net-health, activity, shell badges) refresh
// change-only from the lighter build that skips the MariaDB pinning fetch and the lease
// table - so an idle connected client costs no MariaDB round-trip between lease changes.
//
// The lease-row regions are deliberately NOT re-synced here. Their EXPIRES cells carry
// a server-rendered countdown text that is correct only at render time; re-broadcasting
// the cached fragment every 12s slammed that now-stale text back into the cell, which
// the client-side tick then corrected ~1s later - the visible "flip between a cached
// value and the current one". The rows stay current without the cache re-send: the 4s
// ticker re-renders them whenever the lease set, presence, or expiry bucket changes, and
// between those the client tick keeps the countdown live from the absolute data-expires.
func (s *Server) publishMetricsTick(leases []kea.ActiveLease) {
	s.publishFragments(s.periodicDashboardFragments(leases))
	// Re-sync only the MariaDB-backed pinning regions from their last rendered fragment so
	// a client whose view drifted stale (a dropped/raced push) reconciles within 12s. These
	// carry no client-ticked value, so re-sending the cache is safe (unlike the lease rows).
	for _, region := range []string{"pinned-body", "learnable-body", "pinned-head", "learnable-head", "pinnings", "pinnings-rollup"} {
		s.live.rebroadcastLast(region)
	}
}

// publishDashboard re-renders the dashboard live regions and broadcasts any that
// changed. Event-driven callers (e.g. a profile switch changes the scopes without
// touching leases) use this so the render always runs; per-region hashing still
// suppresses an identical fragment. The ticker uses tickDashboard instead.
func (s *Server) publishDashboard() {
	leases, err := s.kea.GetLeases(1000)
	if err != nil {
		return // return on error to prevent caching / broadcasting a lie
	}
	s.publishDashboardWithLeases(leases)
}

// liveFragment is a rendered live-region fragment paired with the hub region key
// used for change-only hashing. The fragment's own element id is what Datastar
// morphs into the open page.
type liveFragment struct {
	region   string
	fragment string
}

// dashboardFragments renders every live-region fragment from an already-fetched
// lease set. Both the broadcast path (publishDashboardWithLeases) and the
// per-client initial snapshot (handleSSELive) go through here, so the two can
// never disagree on which regions exist or how they render.
//
// Cost: this runs once per lease-set change while a client is connected (the
// ticker gates on leasesSignature; publishDashboard is event-driven). GetState is
// a fast SQLite read and GetLinkStatus is two sysfs reads; the only round-trips
// are the two MariaDB queries, and they fire only when MariaDB is configured and
// only on an actual lease change (infrequent for DHCP). publishIfChanged still
// suppresses the broadcast for any unchanged region, so an idle operator pays the
// render but never the wire - acceptable at single-operator scale, so the
// regions are deliberately not gated on which page each client is viewing.
func (s *Server) dashboardFragments(leases []kea.ActiveLease) []liveFragment {
	ns := s.collectNetSnapshot() // one SnapshotAll shared by the view + lease table
	v := s.buildDashboardViewWith(views.PageData{}, leases, ns, true)

	// Periodic-cheap regions (also refreshed on a metrics-only tick).
	frags := s.periodicFragments(v)

	// Reuse the pinned ports buildDashboardViewWith already fetched (v.Pinned, whose
	// PortIdentity is the same key decodePortIdentity renders), so tagging PortPinned on
	// the leases body costs no second fetchPinnedPorts query on this broadcast.
	pinnedKeys := make(map[string]bool, len(v.Pinned))
	for _, p := range v.Pinned {
		pinnedKeys[p.PortIdentity] = true
	}

	// Lease/MariaDB-backed regions (refreshed only on a lease change or explicit op).
	frags = append(frags,
		liveFragment{"pool-table", renderFragment(views.PoolTableBody(v))},
		liveFragment{"pool-rollup", renderFragment(views.PoolTableRollup(v))},
		liveFragment{"leases-body", renderFragment(views.LeasesBody(s.unifiedLeaseRowsWithPins(leases, ns.Live, ns.Available, pinnedKeys, ns.GgoNames), "", s.mariadb != nil))},
		liveFragment{"recent-leases", renderFragment(views.RecentLeases(v.RecentLeases, v.CanReserve))},
	)

	// Pinned/Learnable were fetched once by buildDashboardViewWith. The dashboard
	// pinnings card and the /pinning page bodies share that one fetch.
	if s.mariadb != nil {
		frags = append(frags,
			liveFragment{"pinnings", renderFragment(views.DashPinningsBody(v.Pinned))},
			liveFragment{"pinnings-rollup", renderFragment(views.DashPinningsRollup(v.Pinned))},
			liveFragment{"pinned-body", renderFragment(views.PinnedBody(v.Pinned, ""))},
			liveFragment{"learnable-body", renderFragment(views.LearnableBody(v.Learnable, ""))},
			// Card heads carry the live count badge + ASCII/hex toggle; pushed so they
			// reconcile with the body (the head is not inside the body region).
			liveFragment{"pinned-head", renderFragment(views.PinnedHead(v.Pinned))},
			liveFragment{"learnable-head", renderFragment(views.LearnableHead(v.Learnable))},
		)
	}
	return frags
}

// periodicFragments are the live regions refreshed on the 12s metrics tick as well
// as on every lease change: the stat tiles, the netmon-derived cards, the activity
// feed, and the shell badges. None require MariaDB or the lease table, so a
// metrics-only tick can refresh them without the pinning/reservation round-trips.
func (s *Server) periodicFragments(v views.DashboardView) []liveFragment {
	state, _ := s.sqlite.GetState(db.LifecycleStateKey)
	shield := s.net.GetLinkStatus("eth0")
	linkState, linkDetail := s.linkTrunkState(shield.LinkState)
	frags := []liveFragment{
		{"dash-tiles", renderFragment(views.StatTiles(v))},
		{"dash-lldp", renderFragment(views.DashLLDP(v.LLDP))},
		{"activity-feed", renderFragment(views.ActivityFeed(v.Activity))},
		{"state-badge", renderFragment(views.StatusPill(s.statusPillView(state, v.NetHealth)))},
		{"sys-health", renderFragment(views.SysHealthIndicator(s.buildSysHealthView(state)))},
		{"link-status", renderFragment(views.LinkBadge(linkState, shield.Interface, linkDetail))},
		{"net-health", renderFragment(views.NetHealthBody(v.NetHealth))},
		{"net-health-rollup", renderFragment(views.NetHealthRollup(v.NetHealth))},
	}
	// The backend-health strip is a shell region (every page) - included here so a
	// connect snapshot and the live tick keep it synced; transitions also push it
	// immediately via publishBackendAlert.
	if s.health != nil {
		frags = append(frags, liveFragment{"backend-alert", renderFragment(views.BackendAlert(s.backendAlertRows()))})
	}
	return frags
}

// periodicDashboardFragments renders only the periodic-cheap regions from a lighter
// view build that skips the MariaDB pinning fetch and the lease table - used by a
// metrics-only tick so an idle connected client costs no MariaDB round-trips.
func (s *Server) periodicDashboardFragments(leases []kea.ActiveLease) []liveFragment {
	ns := s.collectNetSnapshot()
	v := s.buildDashboardViewWith(views.PageData{}, leases, ns, false)
	return s.periodicFragments(v)
}

// publishFragments broadcasts each region fragment, suppressing any unchanged since
// the last broadcast (per-region hashing in publishIfChanged).
func (s *Server) publishFragments(frags []liveFragment) {
	for _, f := range frags {
		s.live.publishIfChanged(f.region, f.fragment)
	}
}

// publishDashboardWithLeases renders the full live-region set from an already-fetched
// lease set and broadcasts any that changed. The fragments morph by element id into
// whichever page is open; on a page lacking an id the patch is a harmless no-op.
func (s *Server) publishDashboardWithLeases(leases []kea.ActiveLease) {
	s.publishFragments(s.dashboardFragments(leases))
}

// leasesSignature is an order-independent fingerprint of the lease set's identity
// (IP + MAC + client-id + count). XOR makes it independent of GetLeases' result
// ordering; lease expiry is deliberately excluded (a renewal must not force a
// re-render). The client-id IS included because a learnable switch port is defined
// entirely by its Option-82 flex-id (the lease client-id): a device gaining/changing
// its Option-82 identity on a STABLE IP+MAC (observed on the Pi: same IP+MAC carrying
// both a normal client-id and an "AV-Edge-3<0x1f>etherN" flex-id) must re-render the
// /pinning learnable list, which it otherwise wouldn't until a full reload.
func leasesSignature(leases []kea.ActiveLease) uint64 {
	var x uint64
	for _, l := range leases {
		x ^= fnv64(l.IPAddress + "|" + l.HWAddress + "|" + l.ClientID)
	}
	return x ^ uint64(len(leases))
}

// presenceSignature fingerprints which leased IPs are currently reachable (per the active
// ARP prober), so tickDashboard re-broadcasts the lease rows when a device crosses the
// online/offline boundary even though the lease set is unchanged. Order-independent XOR;
// only reachable lease IPs contribute, so an unrelated host coming/going does not churn it.
// The "live|" prefix keeps these values disjoint from leasesSignature's IP|MAC hashes.
func presenceSignature(leases []kea.ActiveLease, reachable map[string]bool) uint64 {
	var x uint64
	for _, l := range leases {
		if reachable[l.IPAddress] {
			x ^= fnv64("live|" + l.IPAddress)
		}
	}
	return x
}

// expirySignature folds each lease's absolute expiry (cltt+valid-lft) into the tick
// gate, bucketed to 30s. leasesSignature deliberately excludes expiry so ordinary
// countdown ticking doesn't churn re-renders - but a renewal EXTENDS the deadline,
// and without re-broadcasting the new absolute value the client keeps counting the
// stale baked-in deadline down to a false "expired". Bucketing means only a real
// renewal (which jumps the deadline by far more than 30s) flips the signature; the
// per-region hash still drops the push if the rendered text is unchanged.
func expirySignature(leases []kea.ActiveLease) uint64 {
	var x uint64
	for _, l := range leases {
		exp := leaseExpiryAt(l.Cltt, l.ValidLft)
		x ^= fnv64("exp|" + l.IPAddress + "|" + strconv.FormatInt(exp/30, 10))
	}
	return x
}

// renderFragment renders a templ component to a string for broadcasting over the
// live hub. The components are trusted server-side partials, so a render error
// (which templ effectively never returns for a static tree) yields an empty
// fragment rather than panicking.
func renderFragment(c templ.Component) string {
	var b strings.Builder
	_ = c.Render(context.Background(), &b)
	return b.String()
}

// handleSSELive holds one long-lived SSE connection per client and writes
// published fragments as Datastar patch-elements events until the client
// disconnects. Datastar streams over fetch (not native EventSource), so this
// works over plain HTTP with no TLS/secure-context requirement.
func (s *Server) handleSSELive(w http.ResponseWriter, r *http.Request) {
	sse := datastar.NewSSE(w, r)
	// The page that opened this stream scopes which regions this client receives, so
	// it never gets a patch for a DOM id it lacks. The client passes its path
	// explicitly (?page=) - reliable, unlike Referer (which some referrer policies
	// strip); fall back to Referer, then to "" (send all) if neither is present.
	page := r.URL.Query().Get("page")
	if page == "" {
		page = refererPath(r)
	}
	ch := s.live.subscribe(page)
	defer s.live.unsubscribe(ch)

	ctx := r.Context()

	// One-shot snapshot on connect so a freshly-(re)connected client syncs immediately,
	// before the next change-driven broadcast. It goes straight to THIS client (not the
	// hub), bypassing the change-only gate. The work is slow - GetLeases hits the Kea
	// control socket, dashboardFragments hits MariaDB + renders - so it runs in a
	// goroutine and is funneled through `snap`: a wedged backend then delays only this
	// client's first sync, not the SSE accept itself. All sse writes stay on THIS
	// goroutine (the select loop); the goroutine only computes, never writes sse.
	snap := make(chan string, 8)
	go func() {
		defer close(snap)
		leases, err := s.kea.GetLeases(1000)
		if err != nil {
			return
		}
		for _, f := range s.dashboardFragments(leases) {
			if !regionOnPage(f.region, page) {
				continue
			}
			select {
			case snap <- f.fragment:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case fragment, ok := <-snap:
			if !ok {
				snap = nil // snapshot drained; a nil channel never selects again
				continue
			}
			if err := sse.PatchElements(fragment); err != nil {
				return
			}
		case fragment, ok := <-ch:
			if !ok {
				return
			}
			// Default outer-morph patches by the fragment's element id.
			if err := sse.PatchElements(fragment); err != nil {
				return // client gone; unsubscribe via defer
			}
		}
	}
}
