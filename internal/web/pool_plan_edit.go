package web

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"

	"github.com/starfederation/datastar-go/datastar"
)

// goSizePresets mirrors the wizard's size buttons server-side (the seed source for
// the Small/Medium/Large tabs); Flat/Custom are handled separately.
var goSizePresets = map[string]DeviceCounts{
	"small":  {BPX: 15, MCX: 3, Interface: 3, Others: 15, WAA: 2, Nodes: 25},
	"medium": {BPX: 50, MCX: 20, WPX: 2, Interface: 6, Bridge: 2, Stride: 6, Beacon: 2, Others: 18, Nodes: 120},
	"large":  {BPX: 100, MCX: 40, WPX: 16, Interface: 40, Bridge: 10, Stride: 50, Beacon: 50, Others: 20, Nodes: 300},
}

// defaultSizePreset is the size a brand-new / untouched scope seeds to. It keeps a
// fresh greengo scope from collapsing to a degenerate plan (reserve + catch-alls,
// no device-class pools) when no Counts have been supplied yet.
const defaultSizePreset = "small"

// defaultSeedSize is the size tab to activate for a freshly (re)seeded scope: the
// device-count default for greengo, else "flat" - a non-greengo scope is a single
// dynamic pool, which is exactly what Flat represents (its only other tab is Custom).
func defaultSeedSize(preset string) string {
	if preset == "greengo" {
		return defaultSizePreset
	}
	return "flat"
}

// seedDefaultPlan seeds a plan for a scope, substituting the configured default
// size when the scope carries no device counts (a truly fresh scope). A scope that
// already has counts (e.g. a legacy row loaded from pool_spec) seeds from those.
// Non-greengo presets ignore counts, so the substitution is harmless there.
func seedDefaultPlan(sc ScopeConfig) PoolPlan {
	if sc.Counts == (DeviceCounts{}) {
		sc.Counts = goSizePresets[defaultSizePreset]
	}
	return seedPlan(sc)
}

// handleWizardPoolEdit is the Datastar SSE endpoint for the wizard's pool plan.
// It resolves the scope's plan from the op (seed/size/mode/recompute or a
// structural op applied to the posted plan fields), renders the PoolPlan wired
// for editing, and PatchElements-morphs the #poolplan-<s> region.
func (s *Server) handleWizardPoolEdit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.URL.Query()
	sIdx := q.Get("s")
	op, v := q.Get("op"), q.Get("v")
	mode := orDefault(q.Get("mode"), "simple")
	size := orDefault(q.Get("size"), "custom")
	i := atoiSafe(q.Get("i"))

	prefix := "scopes[" + sIdx + "]"
	sc := ScopeConfig{
		Preset: orDefault(r.FormValue(prefix+"[preset]"), "greengo"),
		CIDR:   orDefault(r.FormValue(prefix+"[cidr]"), "10.0.0.0/24"),
		VlanID: atoiSafe(r.FormValue(prefix + "[vlan]")),
	}
	poolPrefix := prefix + "[pool]"

	switch op {
	case "mode":
		mode = v
		sc.Plan = parsePoolFields(r, poolPrefix, sc.CIDR)
	case "size":
		size = v
		switch v {
		case "flat":
			sc.Plan = flatPlan()
		case "custom":
			sc.Plan = parsePoolFields(r, poolPrefix, sc.CIDR)
		default:
			if c, ok := goSizePresets[v]; ok {
				sc.Counts = c
			}
			sc.Plan = seedPlan(sc)
		}
	case "seed":
		// Restore an EXACT prefilled plan when the form already carries one (the
		// wizard's edit/import path writes the saved scopes[s][pool][...] fields
		// before the data-init seed fires), else derive a fresh plan from the
		// preset/counts. This is what makes "Edit Configuration" keep the operator's
		// pool sizing/reserves instead of resetting to defaults.
		if existing := parsePoolFields(r, poolPrefix, sc.CIDR); len(existing) > 0 {
			sc.Plan = existing
			size = "custom"
			mode = planMode(existing) // reopen in the mode the plan was saved in
		} else {
			// Fresh scope: seed the configured default size so it opens with a sensible
			// plan (and the matching size tab active), not an empty greengo plan.
			sc.Plan = seedDefaultPlan(sc)
			size = defaultSeedSize(sc.Preset)
		}
	case "reseed":
		// The preset dropdown changed: rebuild the plan from the NEW preset, discarding
		// the old pools. Unlike "seed" (which restores the posted plan on edit/import),
		// reseed deliberately ignores the existing fields so e.g. greengo's catch-all +
		// device pools don't linger on a scope switched to dante/sacn/generic.
		sc.Plan = seedDefaultPlan(sc)
		size = defaultSeedSize(sc.Preset)
		mode = "simple"
	case "recompute":
		sc.Plan = parsePoolFields(r, poolPrefix, sc.CIDR)
	case "set-range":
		// An Advanced range edit: derive the missing octet (parsePoolFields) and anchor row
		// i so the surrounding pools repack around it.
		sc.Plan = anchorRangeEdit(parsePoolFields(r, poolPrefix, sc.CIDR), i)
		size = "custom"
	default:
		sc.Plan = applyPoolOp(parsePoolFields(r, poolPrefix, sc.CIDR), op, i, v, mode)
		size = "custom" // a structural edit deviates from any size preset
	}

	// Simple mode is size-driven: strip any Advanced range pins so the size inputs
	// actually drive the layout. Otherwise a leftover pin survives (posted as a
	// hidden field) and LayoutPools keeps honoring it, making the size input a
	// silent no-op. Advanced mode keeps its pins.
	if mode == "simple" {
		for i := range sc.Plan {
			sc.Plan[i].Range = ""
		}
	}

	// Auto-grow the subnet: if the plan's fixed pools no longer fit the chosen CIDR,
	// widen the mask until they do (the operator opted into auto-sizing). The plan
	// renders against the fitted CIDR, and when it changed we also morph the scope's
	// CIDR input so the field, the plan, and the eventual apply all agree.
	origCIDR := sc.CIDR
	sc.CIDR = kea.FitCIDR(sc.CIDR, sc.Plan.ToSpecs())

	view := buildPoolPlanView(sc, nil, false, mode)
	view.ActiveSize = size
	view.SizePresets = true
	view.Heading = "Devices & Pools"
	view.Scope = atoiSafe(sIdx)
	view.RegionID = "poolplan-" + sIdx
	view.FieldPrefix = poolPrefix
	view.EditAction = "/setup/pools/edit"

	sse := datastar.NewSSE(w, r)
	_ = sse.PatchElementTempl(views.PoolPlan(view))
	if sc.CIDR != origCIDR {
		_ = sse.PatchElementTempl(views.CIDRInput(atoiSafe(sIdx), sc.CIDR))
	}
}

// orDefault returns def when s is empty.
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// pool_plan_edit.go is the shared, Datastar-driven pool-plan editor core: the
// PoolPlan fragment renders its entries as form fields (prefix[i][field]); each
// control is a Datastar @post carrying an op; the server parses the fields, applies
// the op, re-renders, and PatchElements-morphs the #poolplan-<scope> region. The
// op application + field parsing are pure, so they are unit-tested here; the same
// engine serves the wizard (staged plan) and /pools (active profile).

// maxPoolsPerScope is the hard cap on pool entries parsed from one form; the loop
// breaks at the first gap, so this only bounds a pathological/hostile submission.
const maxPoolsPerScope = 512

// parsePoolFields reads an ordered PoolPlan from the form fields named
// "<prefix>[i][field]" (kind/class/sizing/count/weight/name/range_start/range_end/range/vendors/icon),
// stopping at the first gap.
func parsePoolFields(r *http.Request, prefix string, cidr string) PoolPlan {
	var plan PoolPlan
	for i := 0; i < maxPoolsPerScope; i++ {
		base := prefix + "[" + strconv.Itoa(i) + "]"
		kind := r.FormValue(base + "[kind]")
		if kind == "" {
			break
		}
		if kind != PoolKindFixed && kind != PoolKindElastic && kind != PoolKindReserve {
			continue // ignore an out-of-set kind rather than persisting it as a silent Fixed default
		}

		var rangeVal string
		start := r.FormValue(base + "[range_start]")
		end := r.FormValue(base + "[range_end]")
		if start != "" || end != "" {
			// Either octet alone is enough: the blank end is completed from the pool's
			// address count, so typing a start OR an end both produce a valid range.
			rangeVal = deriveRange(cidrPrefix(cidr), start, end, atoiSafe(r.FormValue(base+"[count]")))
		} else {
			rangeVal = r.FormValue(base + "[range]")
		}

		plan = append(plan, PoolPlanEntry{
			Kind:    kind,
			Class:   r.FormValue(base + "[class]"),
			Name:    r.FormValue(base + "[name]"),
			Sizing:  r.FormValue(base + "[sizing]"),
			Icon:    r.FormValue(base + "[icon]"),
			Count:   atoiSafe(r.FormValue(base + "[count]")),
			Weight:  atoiSafe(r.FormValue(base + "[weight]")),
			Range:   rangeVal,
			Vendors: splitVendors(r.FormValue(base + "[vendors]")),
		})
	}
	return plan
}

// deriveRange builds a "start - end" pool range from the operator's host-octet inputs,
// completing whichever octet was left blank from the pool's address count: end-only ->
// start = end - count + 1; start-only -> end = start + count - 1; both -> verbatim. prefix
// is the network prefix ending in "." (e.g. "10.0.0."); start/end are host parts. A
// non-positive count is treated as 1. A typed value that won't parse as an IP falls back to
// the lone pinned address; an out-of-subnet derived range is left for LayoutPools to reject.
func deriveRange(prefix, start, end string, count int) string {
	if count < 1 {
		count = 1
	}
	parse := func(host string) (uint32, bool) {
		ip := net.ParseIP(prefix + host).To4()
		if ip == nil {
			return 0, false
		}
		return kea.IPToUint32(ip), true
	}
	switch {
	case start != "" && end != "":
		return prefix + start + " - " + prefix + end
	case end != "":
		if e, ok := parse(end); ok && e >= uint32(count-1) {
			return kea.Uint32ToIP(e-uint32(count-1)).String() + " - " + prefix + end
		}
		return prefix + end
	default: // start != ""
		if s, ok := parse(start); ok {
			return prefix + start + " - " + kea.Uint32ToIP(s+uint32(count-1)).String()
		}
		return prefix + start
	}
}

// anchorRangeEdit makes row i the fixed anchor of an Advanced range edit: it keeps row i's
// (possibly count-derived) explicit range and converts every OTHER pinned row to a
// size-based pool (Range cleared, Count set to its current width) so LayoutPools repacks
// them into the free space around the anchor - the surrounding pools shift gracefully. If
// the result doesn't fit, LayoutPools surfaces the error (foot alert) rather than silently
// overlapping. ponytail: the others repack by size in spec order, so ordering across the
// anchor is not strictly preserved; an order-preserving ripple is the upgrade path.
func anchorRangeEdit(plan PoolPlan, i int) PoolPlan {
	for j := range plan {
		if j == i || plan[j].Range == "" {
			continue
		}
		if lo, hi, ok := kea.ParsePoolRange(plan[j].Range); ok {
			plan[j].Count = int(hi-lo) + 1
		}
		plan[j].Range = ""
	}
	return plan
}

// applyPoolOp mutates an ordered plan by a single editor op. i/v are the op's row
// index and value (e.g. weight delta, size key); mode is the editor mode, which
// gates whether catch-all pools may be removed (Advanced only). Unknown ops return
// the plan unchanged. Value edits (count/name/range) need no op - they arrive in the
// fields and a plain re-render ("recompute") reflects them.
// canDeletePool reports whether the pool with the given class may be removed in the
// given editor mode. The unmatched-device catch-alls (GGO-OTHERS/OTHERS) are safety
// nets, removable only in Advanced mode; any other pool is always removable. Single
// source of truth shared by the applyPoolOp "remove" guard and the UI Locked flag,
// so the two can never drift (rename the token / add a caller and both follow).
func canDeletePool(class, mode string) bool {
	return mode == "advanced" || !kea.IsCatchAll(class)
}

// planHasCatchAll reports whether a plan keeps at least one unmatched-device
// catch-all - the safety net that gives a non-matching device an address instead of
// a Kea NAK.
func planHasCatchAll(plan PoolPlan) bool {
	for _, e := range plan {
		if e.Kind == PoolKindReserve {
			continue
		}
		// A classless pool with no vendor-OUI guard accepts ANY device (it has no
		// client-class test), so it is itself a catch-all - that is exactly the flat
		// preset's single "All devices" pool. A classless pool WITH vendors is OUI-guarded,
		// so it does not count. Without this, ensureGreengoCatchAll wrongly appended
		// GGO-OTHERS/OTHERS to a flat Green-GO scope (the reported extra two pools).
		if kea.IsCatchAll(e.Class) || (e.Class == "" && len(e.Vendors) == 0) {
			return true
		}
	}
	return false
}

// greengoCatchAllError returns a non-empty operator-facing message when a Green-GO
// plan in a non-Advanced context has lost its catch-all pools. Advanced mode
// deliberately permits deleting them, so the guard applies only when mode is not
// "advanced" - this restores the save-time invariant that was dropped (from
// /pools/save and the wizard import path) without fighting Advanced mode.
func greengoCatchAllError(preset string, plan PoolPlan, mode string) string {
	if preset != "greengo" || mode == "advanced" || planHasCatchAll(plan) {
		return ""
	}
	return "Green-GO scope is missing its catch-all pool (GGO-OTHERS / OTHERS); without it, unmatched devices get no address. Keep the catch-all, or remove it deliberately in Advanced mode."
}

// ensureGreengoCatchAll heals an imported Green-GO plan that lost its catch-alls by
// re-appending them from a fresh seed (so the exact GGO-OTHERS/OTHERS entries are
// reused, not hand-built), guaranteeing unmatched devices always get an address.
// Used on the wizard import path, which has no Advanced toggle to gate on; a
// deliberate catch-all removal stays available afterward in the live Advanced
// editor. A no-op for non-greengo presets or a plan that already has a catch-all.
func ensureGreengoCatchAll(sc ScopeConfig) ScopeConfig {
	if sc.Preset != "greengo" || planHasCatchAll(sc.Plan) {
		return sc
	}
	for _, e := range seedDefaultPlan(sc) {
		if kea.IsCatchAll(e.Class) {
			sc.Plan = append(sc.Plan, e)
		}
	}
	return sc
}

func applyPoolOp(plan PoolPlan, op string, i int, v, mode string) PoolPlan {
	switch op {
	case "toggle":
		if ok := i >= 0 && i < len(plan); ok {
			if plan[i].Kind == PoolKindElastic {
				plan[i].Kind = PoolKindFixed
			} else {
				plan[i].Kind = PoolKindElastic
				if plan[i].Weight < 1 {
					plan[i].Weight = 1
				}
			}
		}
	case "weight":
		if i >= 0 && i < len(plan) {
			d := atoiSafe(v)
			w := plan[i].Weight + d
			if w < 1 {
				w = 1
			}
			plan[i].Weight = w
		}
	case "move":
		j := i - 1
		if v == "down" {
			j = i + 1
		}
		if i >= 0 && i < len(plan) && j >= 0 && j < len(plan) {
			plan[i], plan[j] = plan[j], plan[i]
		}
	case "remove":
		// The unmatched-device catch-alls (GGO-OTHERS/OTHERS) are safety nets -
		// protected in Simple mode (the UI also hides their trash). Advanced mode lets
		// the operator delete ANY pool, accepting that without OTHERS a non-matching
		// device gets no address (Kea NAKs it) - their call, it is Advanced mode.
		if i >= 0 && i < len(plan) && canDeletePool(plan[i].Class, mode) {
			plan = append(plan[:i], plan[i+1:]...)
		}
	case "add-pool":
		plan = append(plan, PoolPlanEntry{Kind: PoolKindFixed, Name: "New pool", Sizing: "explicit", Count: 10, Icon: "cpu"})
	case "add-class":
		// v is a Green-GO device class chosen from the greengo Add-pool menu; validate
		// it against the canonical table so a crafted value can't inject an arbitrary
		// class. Duplicates of an already-present class are allowed - Kea fills
		// class-guarded pools in order, and the GGO-OTHERS/OTHERS catch-all invariant
		// is unaffected. Seeded auto-sized (device count) so the operator just sets how
		// many devices; Name/Icon come from the class so it reads identically to a
		// seeded class pool (fixed routing, no icon/vendor editor).
		for _, dc := range kea.DeviceClasses {
			if dc.Name == v {
				plan = append(plan, PoolPlanEntry{Kind: PoolKindFixed, Class: v, Name: dc.Label, Sizing: "auto", Count: 10, Icon: dc.Icon})
				break
			}
		}
	case "add-reserve":
		plan = append(plan, PoolPlanEntry{Kind: PoolKindReserve, Name: "Reserve", Count: 10})
	case "autofill":
		for k := range plan {
			if plan[k].Kind != PoolKindReserve {
				plan[k].Range = ""
				plan[k].Sizing = "auto"
			}
		}
	case "add-custom-oui":
		// OPERATOR-typed: restricted to the first 3 bytes (6 hex) - the simple OUI.
		if i >= 0 && i < len(plan) {
			plan[i].Vendors = addOUIs(plan[i].Vendors, []string{v}, kea.NormalizeOUI6)
		}
	case "remove-vendor":
		if i >= 0 && i < len(plan) {
			target := kea.NormalizeOUI(v)
			out := plan[i].Vendors[:0]
			for _, o := range plan[i].Vendors {
				if o != target {
					out = append(out, o)
				}
			}
			plan[i].Vendors = out
		}
	case "set-icon":
		// v is an icon key from the curated picker (DeviceIcon renders nothing for an
		// unknown key, so a crafted value is harmless).
		if i >= 0 && i < len(plan) {
			plan[i].Icon = v
		}
	}
	return plan
}

func atoiSafe(s string) int { n, _ := strconv.Atoi(s); return n }

// addOUIs normalizes each raw prefix via norm and appends the valid, not-yet-present
// ones to vendors (order-preserving dedup).
func addOUIs(vendors []string, raw []string, norm func(string) string) []string {
	have := map[string]bool{}
	for _, o := range vendors {
		have[o] = true
	}
	for _, r := range raw {
		if o := norm(r); o != "" && !have[o] {
			vendors = append(vendors, o)
			have[o] = true
		}
	}
	return vendors
}

// splitVendors parses a space/comma-separated OUI list into a slice (nil if empty).
func splitVendors(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	if len(f) == 0 {
		return nil
	}
	return f
}

// splitIPByMask splits an IPv4 address string into a greyed-out network prefix
// and an editable host part, used by the Advanced-mode range inputs.
//
// The split is deliberately at the nearest OCTET boundary (≥24 → 3 octets, ≥16 →
// 2, ≥8 → 1), not the exact bit boundary. For octet-aligned masks (/8, /16, /24 -
// /24 being the appliance default) the prefix is exact. For an in-between mask
// (e.g. /22) the prefix is a true-but-loose prefix of every in-subnet address, so
// the host inputs let the operator type a value outside the subnet. That's
// intentional: partial-octet editing is worse UX, and any out-of-subnet range is
// rejected by Kea's config validation (kea -t) on save with a surfaced error,
// rather than being silently accepted. The reassembly side (cidrPrefix) calls
// back into this function, so display-split and reassembly can't drift.
func splitIPByMask(ipStr string, maskSize int) (prefix, host string) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return "", ipStr
	}
	var prefixOctets int
	switch {
	case maskSize >= 24:
		prefixOctets = 3
	case maskSize >= 16:
		prefixOctets = 2
	case maskSize >= 8:
		prefixOctets = 1
	default:
		prefixOctets = 0
	}

	parts := strings.Split(ipStr, ".")
	if len(parts) != 4 {
		return "", ipStr
	}

	prefix = strings.Join(parts[:prefixOctets], ".") + "."
	if prefixOctets == 0 {
		prefix = ""
	}
	host = strings.Join(parts[prefixOctets:], ".")
	return prefix, host
}

// cidrPrefix extracts the static IP network prefix (e.g. "10.0.0.") from a CIDR.
func cidrPrefix(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	maskSize, _ := ipnet.Mask.Size()
	prefix, _ := splitIPByMask(ipnet.IP.String(), maskSize)
	return prefix
}
