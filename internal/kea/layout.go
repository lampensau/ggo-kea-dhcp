package kea

import (
	"fmt"
	"net"
	"strings"
)

// layout.go is the generalized pool allocator for the per-pool scope model
// (Fixed / Elastic-weighted / Reserve + explicit order) the wizard pool plan and
// the flat/custom presets build on. It is additive: the legacy GenerateElasticPools
// path is untouched, and TestLayoutPools_MatchesGoldenElastic proves that the
// greengo configuration expressed as specs reproduces it byte-for-byte.

// PoolKind classifies how a pool is sized in the layout.
type PoolKind int

const (
	// PoolFixed takes a set number of addresses (Size). In the wizard this is the
	// floored count via SizeForClass (Simple) or the exact count (Advanced) - the
	// caller decides.
	PoolFixed PoolKind = iota
	// PoolElastic shares the leftover space with the other elastic pools, by Weight.
	PoolElastic
	// PoolReserve carves out Size addresses that are NOT handed out by DHCP
	// (gateways for static clients, "address islands"); it occupies space so the
	// other pools pack around it, but the renderer emits no Kea pool for it.
	PoolReserve
)

// PoolSpec is one pool in a scope's ordered plan. Size is the address count for
// Fixed/Reserve; Weight (>=1) is the remainder share for Elastic. Class is the
// Kea client-class for a DHCP pool ("" = the catch-all/dynamic pool); Reserve
// carries no class.
type PoolSpec struct {
	Class   string
	Kind    PoolKind
	Size    int      // Fixed / Reserve: number of addresses
	Weight  int      // Elastic: remainder weight (treated as 1 if < 1)
	Range   string   // optional explicit "start - end" pin (Advanced); honored verbatim
	Vendors []string // MAC-OUI prefixes that route devices here (custom vendor pool)
}

// PoolPlacement is a spec with its computed inclusive "start - end" range. Reserve
// placements are returned too (for display); the renderer drops them from the Kea
// config. A zero-size Fixed/Reserve spec yields an empty Range.
type PoolPlacement struct {
	Class string
	Kind  PoolKind
	Range string
}

const (
	layoutMinPool  = 5  // smallest address count an elastic pool may receive
	layoutCatchAll = 10 // floor for the GGO-OTHERS / OTHERS catch-all pools
)

// SizeForClass returns the auto-sized Fixed pool size for a device/catch-all
// class: the forecast count itself, floored to the class minimum (FloorForClass).
// No headroom is added - sizing is WYSIWYG, so the number the operator sets (or a
// preset's count) is the pool size. (The legacy GenerateElasticPools oracle still
// multiplies by a per-class headroom - held test-locally now - and is retained only as
// a historical test-only reference; it no longer mirrors this path.)
func SizeForClass(class string, count int) int {
	return max(count, FloorForClass(class))
}

// fitCIDRFloor is the widest mask FitCIDR will grow a subnet to (a /8 is already
// 16M addresses - far past any sane DHCP scope; the cap just bounds the loop).
const fitCIDRFloor = 8

// FitCIDR widens cidr's mask until the plan's fixed pools and reserves fit, and
// returns the smallest CIDR that accommodates specs. It re-masks the network base
// at each step (so 10.0.0.0/24 -> 10.0.0.0/23 -> ...), stopping at fitCIDRFloor.
// If the input is unparseable or even the widest tried mask can't fit, it returns
// cidr unchanged (the caller's LayoutPools then surfaces the real error). An
// already-fitting CIDR is returned as-is, so the call is idempotent.
func FitCIDR(cidr string, specs []PoolSpec) string {
	// Already fits: return the operator's exact string untouched (don't normalize
	// the network base - "10.0.0.1/24" stays as typed).
	if _, err := LayoutPools(cidr, specs); err == nil {
		return cidr
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return cidr
	}
	// Widen the mask one bit at a time, re-masking the network base each step.
	start, _ := ipnet.Mask.Size()
	for m := start - 1; m >= fitCIDRFloor; m-- {
		base := ip4.Mask(net.CIDRMask(m, 32))
		cand := fmt.Sprintf("%s/%d", base.String(), m)
		if _, err := LayoutPools(cand, specs); err == nil {
			return cand
		}
	}
	return cidr
}

// FloorForClass is the smallest address count a pool of this class may be sized
// to: the catch-all safety-net floor (layoutCatchAll) for GGO-OTHERS/OTHERS, the
// min-pool floor (layoutMinPool) for every other class. The Simple editor uses it
// as the size field's enforced minimum, and ToSpecs applies it to an explicit
// catch-all so the unmatched-device safety net can never shrink below it.
func FloorForClass(class string) int {
	if IsCatchAll(class) {
		return layoutCatchAll
	}
	return layoutMinPool
}

// LayoutPools assigns ranges to an ordered pool plan. The gateway (network+1) is
// reserved implicitly; pools occupy [network+2 .. broadcast-1]. Specs with an
// explicit Range are PINNED at that range (validated, mutually non-overlapping);
// the rest pack into the free gaps in spec order - Fixed/Reserve take their Size
// (first-fit), Elastic pools share the leftover gap space by Weight (deterministic
// rounding, min-pool floor). With no pins and no elastic-undershoot this reduces
// to a contiguous layout from network+2 (so greengo defaults stay byte-identical).
// It errors on a bad/overlapping pin, when the sizes don't fit, or when an unpinned
// pool can't fit a single gap (the caller surfaces it; Auto-Fill repacks).
func LayoutPools(cidr string, specs []PoolSpec) ([]PoolPlacement, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR block: %w", err)
	}
	lo, hi, ok := subnetUsableBounds(ipnet)
	if !ok {
		return nil, fmt.Errorf("subnet too small for any pool")
	}
	poolLo := lo + 1 // network+1 is the gateway; pools start after it
	if poolLo > hi {
		return nil, fmt.Errorf("subnet too small for any pool")
	}

	weightOf := func(s PoolSpec) int {
		if s.Weight < 1 {
			return 1
		}
		return s.Weight
	}

	ranges := make([]string, len(specs))

	// Pass 1: honor pinned (explicit-range) specs and reserve their intervals.
	var pinned []poolIvl
	for i, s := range specs {
		r := strings.TrimSpace(s.Range)
		if r == "" {
			continue
		}
		a, b, ok := ParsePoolRange(r)
		if !ok || a > b {
			return nil, fmt.Errorf("pool %q has an invalid range %q", s.Class, r)
		}
		if a < poolLo || b > hi {
			return nil, fmt.Errorf("pool %q range %s falls outside the subnet's usable addresses (%s - %s)", s.Class, r, u32ToIP(poolLo), u32ToIP(hi))
		}
		for _, iv := range pinned {
			if a <= iv.hi && b >= iv.lo {
				return nil, fmt.Errorf("pinned pools overlap (around %s)", u32ToIP(a))
			}
		}
		pinned = append(pinned, poolIvl{a, b})
		ranges[i] = fmt.Sprintf("%s - %s", u32ToIP(a), u32ToIP(b))
	}
	sortIvls(pinned)
	gaps := freeGaps(poolLo, hi, pinned)
	totalFree := 0
	for _, g := range gaps {
		totalFree += int(g.hi-g.lo) + 1
	}

	// Pass 2: size the UNPINNED specs. Fixed/Reserve take Size; the elastic pools
	// share what's left of the free space by weight.
	sumFixedReserve, sumWeight := 0, 0
	var elasticIdx []int
	for i, s := range specs {
		if ranges[i] != "" {
			continue // pinned - its range defines its size
		}
		if s.Kind == PoolElastic {
			sumWeight += weightOf(s)
			elasticIdx = append(elasticIdx, i)
			continue
		}
		if s.Size < 0 {
			return nil, fmt.Errorf("pool %q has a negative size", s.Class)
		}
		sumFixedReserve += s.Size
	}
	if sumFixedReserve > totalFree {
		return nil, fmt.Errorf("subnet too small: fixed pools and reserves need %d addresses, only %d free", sumFixedReserve, totalFree)
	}
	sizes := make([]int, len(specs))
	for i, s := range specs {
		if ranges[i] == "" && s.Kind != PoolElastic {
			sizes[i] = s.Size
		}
	}
	if len(elasticIdx) > 0 {
		remainder := totalFree - sumFixedReserve
		assigned := 0
		for _, i := range elasticIdx {
			sz := remainder * weightOf(specs[i]) / sumWeight
			sizes[i] = sz
			assigned += sz
		}
		if leftover := remainder - assigned; leftover > 0 {
			best := elasticIdx[0]
			for _, i := range elasticIdx[1:] {
				if weightOf(specs[i]) > weightOf(specs[best]) {
					best = i
				}
			}
			sizes[best] += leftover
		}
		for _, i := range elasticIdx {
			if sizes[i] < layoutMinPool {
				return nil, fmt.Errorf("subnet too small for the configured pools: elastic pool %q would get only %d addresses (min %d) - reduce device counts or use a larger subnet", specs[i].Class, sizes[i], layoutMinPool)
			}
		}
	}

	// Pass 3: place the unpinned specs into the free gaps, in spec order (first-fit
	// - the lowest gap that fits - so with a single gap this is contiguous). A
	// Fixed/Reserve pool that fits no gap is an error (its exact size matters); an
	// Elastic pool instead caps to its largest gap, since a pool is one contiguous
	// range and can't span fragmented free space.
	for i := range specs {
		if ranges[i] != "" {
			continue
		}
		sz := sizes[i]
		if sz <= 0 {
			continue // zero-size fixed/reserve → no range emitted
		}
		gi := firstFitGap(gaps, sz)
		if gi < 0 {
			if specs[i].Kind != PoolElastic {
				return nil, fmt.Errorf("pool %q (%d addresses) does not fit any free gap - try Auto-Fill", specs[i].Class, sz)
			}
			if gi = largestGapIdx(gaps); gi < 0 {
				return nil, fmt.Errorf("no free space left for elastic pool %q", specs[i].Class)
			}
			sz = min(sz, int(gaps[gi].hi-gaps[gi].lo)+1)
			// Pass 2 guaranteed >= layoutMinPool against TOTAL free space, but a single
			// gap can be smaller when pinned ranges fragment the subnet. Re-check so we
			// error rather than silently emit a sub-floor pool.
			if sz < layoutMinPool {
				return nil, fmt.Errorf("subnet too fragmented for elastic pool %q: its largest free gap holds only %d addresses (min %d) - try Auto-Fill or free a pinned range", specs[i].Class, sz, layoutMinPool)
			}
		}
		g := gaps[gi]
		end := g.lo + uint32(sz) - 1
		ranges[i] = fmt.Sprintf("%s - %s", u32ToIP(g.lo), u32ToIP(end))
		gaps = shrinkGap(gaps, gi, end)
	}

	out := make([]PoolPlacement, len(specs))
	for i, s := range specs {
		out[i] = PoolPlacement{Class: s.Class, Kind: s.Kind, Range: ranges[i]}
	}
	return out, nil
}

// sortIvls sorts intervals ascending by low bound (small enough that an explicit
// helper is clearer than sort.Slice for this hot, tiny slice).
func sortIvls(ivs []poolIvl) {
	for i := 1; i < len(ivs); i++ {
		for j := i; j > 0 && ivs[j].lo < ivs[j-1].lo; j-- {
			ivs[j], ivs[j-1] = ivs[j-1], ivs[j]
		}
	}
}
