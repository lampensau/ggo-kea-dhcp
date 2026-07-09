package web

import (
	"errors"
	"ggo-kea-dhcp/internal/appliance"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/starfederation/datastar-go/datastar"
)

// handlePools renders the dedicated DHCP-pool management page: each active scope's
// pool plan (seeded from its preset+counts when it has no explicit plan yet) with
// the live Utilization column, wired for editing. Editing is the same PoolPlan
// component as the wizard, minus the network/scope chrome; each scope is a form
// targeted by its index so an op/save posts only that scope's fields.
func (s *Server) handlePools(w http.ResponseWriter, r *http.Request) {
	_, _, scopes, _ := s.activeProfileScopes() // id-ordered so the edit index is stable
	rawLeases, _ := s.kea.GetLeases(r.Context(), defaultLeasePageSize)
	leases := parseLeases(rawLeases)

	boxUplink, _, _ := s.uplinkSettings()
	v := views.PoolsView{Page: s.pageData(w, r, "DHCP Pools"), Profiles: s.listProfiles()}
	for i, sc := range scopes {
		v.Scopes = append(v.Scopes, views.PoolScopeView{
			Title: poolScopeTitle(sc),
			// Open in the mode the scope was last saved in (Simple/Advanced persists).
			Plan:            poolsEditView(sc, i, leases, planMode(sc.Plan)),
			Services:        s.scopeServicesView(sc, i),
			UplinkEnabled:   sc.Uplink.Enabled,
			UplinkAvailable: boxUplink,
		})
	}
	s.renderTempl(w, r, views.Pools(v))
}

// scopeServicesView builds the /pools "Network services" panel for one scope: its
// saved gateway/DNS/lease overrides + extra options and the morph region addressed by
// the scope's index. There is no SaveAction - the scope's single pool-plan "Save
// changes" button persists this panel too (both live in the same per-scope form). The
// derived gateway (.1) and the global lease default are shown as placeholders so an
// empty field reads as "inherit".
func (s *Server) scopeServicesView(sc ScopeConfig, idx int) views.ScopeServicesView {
	opts := make([]views.ScopeOptionRow, 0, len(sc.Services.Options))
	for _, o := range sc.Services.Options {
		opts = append(opts, views.ScopeOptionRow{Name: o.Name, Data: o.Data})
	}
	lease := ""
	if sc.Services.LeaseLifetime > 0 {
		lease = strconv.Itoa(sc.Services.LeaseLifetime)
	}
	derived := ""
	if _, ipnet, err := net.ParseCIDR(sc.CIDR); err == nil {
		derived = kea.IncIP(ipnet.IP, 1).String()
	}
	return views.ScopeServicesView{
		RegionID:       "svc-" + strconv.Itoa(idx),
		Gateway:        sc.Services.Gateway,
		DNS:            sc.Services.DNS,
		LocalDNS:       sc.Services.LocalDNS,
		Lease:          lease,
		DerivedGateway: derived,
		GlobalLease:    s.leaseLifetime(),
		Options:        opts,
	}
}

// planMode derives the editor mode from a persisted plan: "advanced" if any pool
// carries an explicit range pin, else "simple". A range pin is only ever set by
// the Advanced range-octet inputs (Simple auto-derives ranges), so it is the
// reliable Advanced marker. Sizing can no longer be used: Simple now also persists
// "explicit" sizing (the operator sets each pool's address size directly), so
// explicit no longer implies Advanced.
func planMode(plan PoolPlan) string {
	for _, e := range plan {
		if e.Range != "" {
			return "advanced"
		}
	}
	return "simple"
}

// poolsEditView builds the editable PoolPlan view for one active-profile scope on
// the /pools page: the computed plan (ranges + live utilization) wired to the
// /pools op + save endpoints, addressed by the scope's id-order index. Unlike the
// wizard it has no size-preset tabs (full per-pool editing on the live scopes).
func poolsEditView(sc ScopeConfig, idx int, leases []parsedLease, mode string) views.PoolPlanView {
	v := buildPoolPlanView(sc, leases, true, mode)
	v.Heading = "Address Pools"
	v.Scope = idx
	v.RegionID = "poolplan-" + strconv.Itoa(idx)
	v.FieldPrefix = "scopes[" + strconv.Itoa(idx) + "][pool]"
	v.EditAction = "/pools/edit"
	v.SaveAction = "/pools/save?s=" + strconv.Itoa(idx) + "&mode=" + v.Mode
	return v
}

// handlePoolsPlanOp is the Datastar SSE op endpoint for the /pools editor (POST
// /pools/edit). It resolves the targeted active-profile scope by index, applies
// the op to the plan parsed from the posted fields, and PatchElements-morphs the
// scope's #poolplan-<s> region. Structural state lives in the form, so this is
// stateless between ops; nothing persists until Save.
func (s *Server) handlePoolsPlanOp(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.URL.Query()
	sIdx := atoiSafe(q.Get("s"))
	op, val := q.Get("op"), q.Get("v")
	mode := orDefault(q.Get("mode"), "simple")
	i := atoiSafe(q.Get("i"))

	sse := datastar.NewSSE(w, r)
	_, _, scopes, ok := s.activeProfileScopes()
	if !ok || sIdx < 0 || sIdx >= len(scopes) {
		toast(sse, "No active profile to edit.", "error")
		return
	}
	sc := scopes[sIdx]
	poolPrefix := "scopes[" + strconv.Itoa(sIdx) + "][pool]"
	switch op {
	case "mode":
		mode = val
		sc.Plan = parsePoolFields(r, poolPrefix, sc.CIDR)
	case "recompute":
		sc.Plan = parsePoolFields(r, poolPrefix, sc.CIDR)
	case "set-range":
		// Advanced range edit: derive the missing octet and anchor row i so the surrounding
		// pools repack around it (anchorRangeEdit).
		sc.Plan = anchorRangeEdit(parsePoolFields(r, poolPrefix, sc.CIDR), i)
	default:
		sc.Plan = applyPoolOp(parsePoolFields(r, poolPrefix, sc.CIDR), op, i, val, mode)
	}

	// Simple mode is size-driven (see StripRangePins; same invariant as the wizard editor).
	if mode == "simple" {
		sc.Plan.StripRangePins()
	}

	rawLeases, _ := s.kea.GetLeases(r.Context(), defaultLeasePageSize)
	leases := parseLeases(rawLeases)
	_ = sse.PatchElementTempl(views.PoolPlan(poolsEditView(sc, sIdx, leases, mode)))
}

// handlePoolsPlanSave persists one scope's edited plan (POST /pools/save?s=&mode=).
// It validates the candidate config (render + kea -t) before writing pool_plan and
// soft-reconciling (a pool change never re-IPs the box), then re-renders the saved
// region and toasts the outcome.
func (s *Server) handlePoolsPlanSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.URL.Query()
	sIdx := atoiSafe(q.Get("s"))
	mode := orDefault(q.Get("mode"), "simple")

	sse := datastar.NewSSE(w, r)
	toastErr := func(msg string) { toast(sse, msg, "error") }

	profileID, ids, scopes, ok := s.activeProfileScopes()
	if !ok || sIdx < 0 || sIdx >= len(scopes) {
		toastErr("No active profile to edit.")
		return
	}
	sc := scopes[sIdx]
	plan := parsePoolFields(r, "scopes["+strconv.Itoa(sIdx)+"][pool]", sc.CIDR)
	if len(plan) == 0 {
		toastErr("Nothing to save - the pool plan is empty.")
		return
	}
	sc.Plan = plan

	// Simple mode is size-driven (see StripRangePins) - a Simple save must persist a
	// size-driven plan so planMode() does not reopen the scope as Advanced.
	if mode == "simple" {
		sc.Plan.StripRangePins()
	}

	// One Save per scope: the pool plan AND the Network services panel live in the
	// same per-scope form, so this single handler persists both. A services parse error
	// (bad gateway/DNS/lease) aborts the whole save - the scope is saved atomically.
	svc, serr := parseScopeServices(
		r.FormValue("gateway"), r.FormValue("dns"), r.FormValue("lease"), r.FormValue("local_dns"),
		r.Form["opt_name[]"], r.Form["opt_data[]"],
	)
	if serr != nil {
		toastErr(serr.Error())
		return
	}
	sc.Services = svc
	// Per-scope WiFi-uplink toggle (route this scope through the box-level wlan0). The
	// SSID/password are box-level, so only Enabled is per-scope.
	sc.Uplink.Enabled = r.FormValue("uplink") == "true"

	// Restore the dropped invariant: a Simple-mode Green-GO save must keep its
	// catch-all (mode here is the editor's explicit ?mode=, so an Advanced delete is
	// correctly exempt and this never false-positives a legitimate Advanced save).
	if msg := greengoCatchAllError(sc.Preset, sc.Plan, mode); msg != "" {
		toastErr(msg)
		return
	}

	// Validate the whole profile with this scope's edits before persisting: render +
	// kea -t rejects an overlapping/out-of-subnet pool range OR a malformed option here.
	candidate := make([]ScopeConfig, len(scopes))
	copy(candidate, scopes)
	candidate[sIdx] = sc
	cfg, _, err := s.recon.RenderKeaForScopes(candidate)
	if err == nil {
		err = kea.TestConfig(cfg)
	}
	if err != nil {
		toastErr("Invalid configuration: " + err.Error())
		return
	}

	pj, perr := sc.PlanJSON()
	sj, serr2 := sc.ServicesJSON()
	uj, uerr := sc.UplinkJSON()
	if e := errors.Join(perr, serr2, uerr); e != nil {
		toastErr("Failed to save: " + e.Error())
		return
	}
	if _, e := s.sqlite.Exec("UPDATE scopes SET pool_plan = ?, services_json = ?, uplink_json = ? WHERE id = ?",
		nilIfEmpty(pj), nilIfEmpty(sj), uj, ids[sIdx]); e != nil {
		toastErr("Failed to save: " + e.Error())
		return
	}

	// Soft reconcile: re-render + Kea config-reload. CIDR/VLAN are unchanged by a pool
	// or services edit, so the appliance does not re-IP. Serialized against an in-flight
	// apply/switch via the shared guard; if one is running, the edit is saved and takes
	// effect on the next reload rather than racing a second reconcile.
	reloaded := false
	if s.beginReconcile() {
		if e := s.ReconcileApplianceState(ModeConverge, profileID); e != nil {
			log.Printf("[Pools] soft reconcile after scope save reported: %v", e)
		} else {
			reloaded = true
		}
		s.endReconcile()
	} else {
		log.Printf("[Pools] soft reconcile deferred - a configuration change is in progress")
	}
	_ = s.sqlite.LogAudit(s.getActor(r), "EDIT_POOLS", sc.CIDR, "", "", "SUCCESS")

	msg := "Scope saved - Kea reloaded."
	if !reloaded {
		msg = "Scope saved - it will take effect on the next reload."
	}
	rawLeases, _ := s.kea.GetLeases(r.Context(), defaultLeasePageSize)
	_ = sse.PatchElementTempl(views.ScopeServices(s.scopeServicesView(sc, sIdx)))
	_ = sse.PatchElementTempl(views.PoolPlan(poolsEditView(sc, sIdx, parseLeases(rawLeases), mode)))
	toast(sse, msg, "success")
}

// nilIfEmpty returns nil for an empty string so an UPDATE writes SQL NULL (the
// "unset" sentinel the loaders treat as absent), or the string otherwise.
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// poolScopeTitle labels a scope on the /pools page: its preset + CIDR (+ VLAN).
func poolScopeTitle(sc ScopeConfig) string {
	// The CIDR is shown once, in the pool-plan sub-heading (pool-plan-sub); the
	// scope card title carries the operator's name (or the derived preset) plus the
	// VLAN, so /pools doesn't print the subnet twice directly below itself.
	title := appliance.PresetLabel(sc.Preset)
	if sc.Name != "" {
		title = sc.Name
	}
	if sc.VlanID > 0 {
		title += " · VLAN " + strconv.Itoa(sc.VlanID)
	}
	return title
}

// activeProfileScopes loads the active profile id + its scopes (id-ordered, so the
// editor's scope index matches the rendered order), or ok=false when there's no
// active profile. The returned ids[i] is the scopes table id for scopes[i], used to
// persist a single scope's edits in place.
func (s *Server) activeProfileScopes() (profileID int, ids []int, scopes []ScopeConfig, ok bool) {
	if err := s.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID); err != nil {
		return 0, nil, nil, false
	}
	rows, err := s.sqlite.Query("SELECT id FROM scopes WHERE profile_id = ? ORDER BY id", profileID)
	if err != nil {
		return 0, nil, nil, false
	}
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	errIter := rows.Err()
	rows.Close()
	if errIter != nil {
		return 0, nil, nil, false
	}
	scopes, err = s.loadScopeConfigs(profileID)
	if err != nil || len(scopes) != len(ids) {
		return 0, nil, nil, false
	}
	return profileID, ids, scopes, true
}

// poolRowIcon picks a pool row's icon: a known Kea class (device class or catch-all)
// takes its canonical icon from the class table - so a table change applies
// everywhere, including already-saved plans - while a custom/vendor pool (no class)
// keeps the operator-picked icon stored on the entry.
func poolRowIcon(e PoolPlanEntry) string {
	if e.Class != "" {
		_, icon, _ := kea.ClassMetadata(e.Class)
		return icon
	}
	return e.Icon
}

// parsedLease is one lease pre-digested for pool-occupancy math: the IPv4 as a
// uint32 plus the device class. parseLeases runs ONCE per build; the per-scope
// subnet filter and per-pool range tests are then plain integer compares. The
// always-on 12s sampler (samplePoolUtil) walks every scope of the active profile
// viewer-independently, so re-running net.ParseIP/ClassifyMAC per lease per scope
// multiplies the per-sample cost by the scope count on a trunk.
type parsedLease struct {
	ip    uint32
	class string
}

// parseLeases digests the lease list for buildPoolPlanView/poolDataForScope.
// Leases with an unparseable address are dropped - they can't fall inside any
// subnet or pool, so no occupancy path could count them anyway.
func parseLeases(leases []kea.ActiveLease) []parsedLease {
	out := make([]parsedLease, 0, len(leases))
	for _, l := range leases {
		ip := net.ParseIP(l.IPAddress).To4()
		if ip == nil {
			continue
		}
		out = append(out, parsedLease{ip: kea.IPToUint32(ip), class: classifyMAC(l.HWAddress)})
	}
	return out
}

func buildPoolPlanView(sc ScopeConfig, leases []parsedLease, showUtil bool, mode string) views.PoolPlanView {
	mode = orDefault(mode, "simple")
	plan := sc.Plan
	if len(plan) == 0 {
		plan = seedDefaultPlan(sc)
	}
	// Simple mode: the editable number is the pool's address SIZE, never below the
	// class floor. Clamp explicit Fixed sizes up to the floor BEFORE layout so the
	// shown number and the actual placed pool agree (an auto pool is already floored
	// by SizeForClass; a below-floor explicit size would otherwise place small while
	// the field rendered the floor). Clamp a copy - this is the display path.
	if mode != "advanced" {
		clamped := make(PoolPlan, len(plan))
		copy(clamped, plan)
		for i := range clamped {
			if clamped[i].Kind == PoolKindFixed && clamped[i].Sizing == "explicit" {
				clamped[i].Count = max(clamped[i].Count, kea.FloorForClass(clamped[i].Class))
			}
		}
		plan = clamped
	}
	v := views.PoolPlanView{Mode: mode, ShowUtil: showUtil, Subnet: sc.CIDR, Greengo: sc.Preset == "greengo"}

	_, ipnet, err := net.ParseCIDR(sc.CIDR)
	if err != nil {
		return v
	}
	v.Gateway = kea.IncIP(ipnet.IP, 1).String()
	placements, perr := kea.LayoutPools(sc.CIDR, plan.ToSpecs())
	if perr != nil {
		// A bad/overlapping range pin (Advanced edit) - surface it in the foot alert
		// so the operator can fix the offending range (the pin values stay in their
		// inputs). The rows render without ranges until it resolves.
		v.Issue = perr.Error()
	}

	// Filter leases that belong to this scope's subnet (integer compare against the
	// subnet bounds - the leases were parsed once by parseLeases). A CIDR that is
	// not plain IPv4 (both the base and the mask must convert) gets the empty
	// range lo=1,hi=0 so no lease matches - the rows still render and LayoutPools'
	// error surfaces in the foot alert, same as before the pre-parse.
	subLo, subHi := uint32(1), uint32(0)
	if ip4, m4 := ipnet.IP.To4(), net.IP(ipnet.Mask).To4(); ip4 != nil && m4 != nil {
		subLo = kea.IPToUint32(ip4)
		subHi = subLo | ^kea.IPToUint32(m4)
	}
	var scopeLeases []parsedLease
	for _, l := range leases {
		if l.ip >= subLo && l.ip <= subHi {
			scopeLeases = append(scopeLeases, l)
		}
	}

	classCounts := map[string]int{}
	for _, l := range scopeLeases {
		classCounts[l.class]++
	}

	allocated := 0
	for i, e := range plan {
		rng := ""
		if perr == nil && i < len(placements) {
			rng = placements[i].Range
		}
		capacity := parseRangeCapacity(rng)
		allocated += capacity

		// Parse CIDR prefix and host parts
		var prefix, startPin, endPin, startPlaceholder, endPlaceholder string
		if ipnet != nil {
			maskSize, _ := ipnet.Mask.Size()
			// 1. Split the computed display range (rng), e.g. "10.0.0.235 - 10.0.0.244"
			if rng != "" {
				if pref, st, ed, ok := splitRange(rng, maskSize); ok {
					prefix, startPlaceholder, endPlaceholder = pref, st, ed
				}
			}
			// 2. Split the RangePin (e.Range), e.g. "10.0.0.235 - 10.0.0.244" (if set)
			if e.Range != "" {
				if pref, st, ed, ok := splitRange(e.Range, maskSize); ok {
					prefix, startPin, endPin = pref, st, ed
				} else {
					// Fallback: if there's no separator, treat the whole pin as startPin (without prefix if possible)
					pref, st := splitIPByMask(e.Range, maskSize)
					prefix = pref
					startPin = st
				}
			}
		}

		// In Simple mode the editable number is the pool's address SIZE (capacity),
		// floored to the class minimum (5 normal, 10 catch-all) - no headroom maths,
		// what you set is what you get. In Advanced it stays the explicit count/size
		// the operator typed (ranges give exact control), floored to 1.
		floor := 1
		num := e.Count
		if v.Mode != "advanced" {
			floor = kea.FloorForClass(e.Class)
			num = capacity
		}
		count := max(num, floor)

		row := views.PoolPlanRow{
			Key:              e.Class,
			Name:             e.Name,
			Icon:             poolRowIcon(e),
			Codes:            classCodes(e.Class),
			Vendor:           strings.Join(e.Vendors, " · "),
			VendorList:       e.Vendors,
			Range:            rng,     // computed, for DISPLAY only
			RangePin:         e.Range, // the explicit pin (empty for auto pools) - what posts back
			Prefix:           prefix,
			Start:            startPin,
			End:              endPin,
			StartPlaceholder: startPlaceholder,
			EndPlaceholder:   endPlaceholder,
			Reserve:          e.Kind == PoolKindReserve,
			Elastic:          e.Kind == PoolKindElastic,
			// Catch-alls (GGO-OTHERS/OTHERS) are safety nets - protected in Simple mode,
			// but Advanced mode lets the operator delete ANY pool (they own the layout).
			Locked:       !canDeletePool(e.Class, v.Mode),
			Weight:       max(e.Weight, 1),
			Count:        count,
			Floor:        floor,
			Size:         capacity,
			IconEditable: e.Class == "" && e.Kind != PoolKindReserve, // non-Green-GO pools pick an icon
		}
		if e.Kind != PoolKindReserve && capacity > 0 {
			used := 0
			if e.Class != "" {
				used = classCounts[e.Class]
			} else if lo, hi, ok := kea.ParsePoolRange(rng); ok {
				for _, l := range scopeLeases {
					if l.ip >= lo && l.ip <= hi {
						used++
					}
				}
			}
			row.Used = used
			row.Capacity = capacity
			row.Percent = used * 100 / capacity
		}
		v.Rows = append(v.Rows, row)
	}

	// Free reserve = usable pool space (network+2 .. broadcast-1) minus allocated.
	if maskSize, _ := ipnet.Mask.Size(); maskSize <= 30 {
		total := 1 << (32 - maskSize)
		if usable := total - 3; usable > allocated { // -network -gateway -broadcast
			v.FreeIPs = usable - allocated
		}
	}
	return v
}

// classCodes returns the device-model codes shown under a Green-GO pool's name,
// or "" for catch-alls and non-Green-GO pools. Sourced from the canonical
// kea.DeviceClasses table (via ClassMetadata) so it can't drift from a duplicate.
func classCodes(class string) string {
	_, _, codes := kea.ClassMetadata(class)
	return codes
}
