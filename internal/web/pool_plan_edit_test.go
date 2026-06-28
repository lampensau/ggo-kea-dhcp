package web

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

// TestParsePoolFields reads an ordered plan from prefixed form fields.
func TestParsePoolFields(t *testing.T) {
	v := url.Values{}
	v.Set("scopes[0][pool][0][kind]", "reserve")
	v.Set("scopes[0][pool][0][name]", "Static reserve")
	v.Set("scopes[0][pool][0][count]", "18")
	v.Set("scopes[0][pool][1][kind]", "fixed")
	v.Set("scopes[0][pool][1][class]", "GGO-WP-X")
	v.Set("scopes[0][pool][1][sizing]", "auto")
	v.Set("scopes[0][pool][1][count]", "8")
	v.Set("scopes[0][pool][2][kind]", "elastic")
	v.Set("scopes[0][pool][2][class]", "GGO-BPX")
	v.Set("scopes[0][pool][2][weight]", "3")
	r := httptest.NewRequest("POST", "/x", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plan := parsePoolFields(r, "scopes[0][pool]", "10.0.0.0/24")
	if len(plan) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(plan), plan)
	}
	if plan[0].Kind != "reserve" || plan[0].Count != 18 {
		t.Errorf("entry 0 = %+v", plan[0])
	}
	if plan[1].Kind != "fixed" || plan[1].Class != "GGO-WP-X" || plan[1].Count != 8 {
		t.Errorf("entry 1 = %+v", plan[1])
	}
	if plan[2].Kind != "elastic" || plan[2].Weight != 3 {
		t.Errorf("entry 2 = %+v", plan[2])
	}
}

// TestParsePoolFieldsRejectsBadKind: an out-of-set kind is dropped, not persisted as
// a silent Fixed default. The valid entry after it is still read (continue, not break).
func TestParsePoolFieldsRejectsBadKind(t *testing.T) {
	v := url.Values{}
	v.Set("scopes[0][pool][0][kind]", "bogus")
	v.Set("scopes[0][pool][0][count]", "9")
	v.Set("scopes[0][pool][1][kind]", "reserve")
	v.Set("scopes[0][pool][1][count]", "18")
	r := httptest.NewRequest("POST", "/x", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plan := parsePoolFields(r, "scopes[0][pool]", "10.0.0.0/24")
	if len(plan) != 1 || plan[0].Kind != PoolKindReserve {
		t.Fatalf("bad kind must be dropped, valid entry kept: %+v", plan)
	}
}

func TestApplyPoolOp(t *testing.T) {
	base := func() PoolPlan {
		return PoolPlan{
			{Kind: PoolKindFixed, Class: "A", Count: 8},
			{Kind: PoolKindFixed, Class: "B", Count: 4},
			{Kind: PoolKindElastic, Class: "BPX", Weight: 1},
		}
	}
	// toggle Fixed → Elastic (weight defaults to 1).
	if p := applyPoolOp(base(), "toggle", 0, "", "simple"); p[0].Kind != PoolKindElastic || p[0].Weight != 1 {
		t.Errorf("toggle: %+v", p[0])
	}
	// weight delta, floored at 1.
	if p := applyPoolOp(base(), "weight", 2, "2", "simple"); p[2].Weight != 3 {
		t.Errorf("weight +2: got %d", p[2].Weight)
	}
	if p := applyPoolOp(base(), "weight", 2, "-5", "simple"); p[2].Weight != 1 {
		t.Errorf("weight floor: got %d", p[2].Weight)
	}
	// move down swaps 0 and 1.
	if p := applyPoolOp(base(), "move", 0, "down", "simple"); p[0].Class != "B" || p[1].Class != "A" {
		t.Errorf("move down: %+v", p)
	}
	// remove drops the entry.
	if p := applyPoolOp(base(), "remove", 1, "", "simple"); len(p) != 2 || p[1].Class != "BPX" {
		t.Errorf("remove: %+v", p)
	}
	// add appends.
	if p := applyPoolOp(base(), "add-pool", 0, "", "simple"); len(p) != 4 || p[3].Kind != PoolKindFixed {
		t.Errorf("add-pool: %+v", p)
	}
	if p := applyPoolOp(base(), "add-reserve", 0, "", "simple"); len(p) != 4 || p[3].Kind != PoolKindReserve {
		t.Errorf("add-reserve: %+v", p)
	}
	// out-of-range index is a no-op (no panic).
	if p := applyPoolOp(base(), "toggle", 99, "", "simple"); len(p) != 3 {
		t.Errorf("oob toggle changed length: %+v", p)
	}
	// The catch-alls (GGO-OTHERS/OTHERS) are safety nets - remove refuses them in
	// Simple mode, but Advanced mode may delete any pool.
	withCatchAll := PoolPlan{
		{Kind: PoolKindFixed, Class: "A", Count: 8},
		{Kind: PoolKindFixed, Class: kea.ClassNameGGOOthers, Count: 0},
		{Kind: PoolKindElastic, Class: kea.ClassNameOthers, Weight: 1},
	}
	if p := applyPoolOp(withCatchAll, "remove", 1, "", "simple"); len(p) != 3 {
		t.Errorf("simple remove must not delete GGO-OTHERS: %+v", p)
	}
	if p := applyPoolOp(withCatchAll, "remove", 2, "", "simple"); len(p) != 3 {
		t.Errorf("simple remove must not delete OTHERS: %+v", p)
	}
	if p := applyPoolOp(withCatchAll, "remove", 0, "", "simple"); len(p) != 2 {
		t.Errorf("remove must still drop a normal pool: %+v", p)
	}
	// Advanced mode CAN delete a catch-all.
	if p := applyPoolOp(withCatchAll, "remove", 2, "", "advanced"); len(p) != 2 {
		t.Errorf("advanced remove must delete OTHERS: %+v", p)
	}

	// add-custom-oui normalizes a single operator-typed 6-hex OUI onto a pool and
	// dedups; remove-vendor drops one. (The curated add-vendor op was removed.)
	vp := func() PoolPlan { return PoolPlan{{Kind: PoolKindFixed, Class: "", Name: "Custom"}} }
	if p := applyPoolOp(vp(), "add-custom-oui", 0, "00:1D:C1", "simple"); len(p[0].Vendors) != 1 || p[0].Vendors[0] != "001dc1" {
		t.Errorf("add-custom-oui normalize: %+v", p[0].Vendors)
	}
	withV := PoolPlan{{Kind: PoolKindFixed, Vendors: []string{"001dc1", "e44f29"}}}
	if p := applyPoolOp(withV, "add-custom-oui", 0, "001dc1", "simple"); len(p[0].Vendors) != 2 {
		t.Errorf("add-custom-oui should dedup: %+v", p[0].Vendors)
	}
	withV2 := PoolPlan{{Kind: PoolKindFixed, Vendors: []string{"001dc1", "e44f29"}}}
	if p := applyPoolOp(withV2, "remove-vendor", 0, "00:1d:c1", "simple"); len(p[0].Vendors) != 1 || p[0].Vendors[0] != "e44f29" {
		t.Errorf("remove-vendor: %+v", p[0].Vendors)
	}
}

func TestParsePoolFieldsSplitRange(t *testing.T) {
	v := url.Values{}
	v.Set("scopes[0][pool][0][kind]", "fixed")
	v.Set("scopes[0][pool][0][name]", "My fixed pool")
	v.Set("scopes[0][pool][0][range_start]", "123")
	v.Set("scopes[0][pool][0][range_end]", "145")
	r := httptest.NewRequest("POST", "/x", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plan := parsePoolFields(r, "scopes[0][pool]", "10.0.0.0/24")
	if len(plan) != 1 {
		t.Fatalf("got %d entries, want 1", len(plan))
	}
	if plan[0].Range != "10.0.0.123 - 10.0.0.145" {
		t.Errorf("expected assembled range to be 10.0.0.123 - 10.0.0.145, got %q", plan[0].Range)
	}
}

// TestDeriveRange: a lone start OR end completes the other octet from the pool's count.
func TestDeriveRange(t *testing.T) {
	if got := deriveRange("10.0.0.", "", "244", 10); got != "10.0.0.235 - 10.0.0.244" {
		t.Errorf("end-only: got %q, want 10.0.0.235 - 10.0.0.244", got)
	}
	if got := deriveRange("10.0.0.", "235", "", 10); got != "10.0.0.235 - 10.0.0.244" {
		t.Errorf("start-only: got %q, want 10.0.0.235 - 10.0.0.244", got)
	}
	if got := deriveRange("10.0.0.", "100", "150", 10); got != "10.0.0.100 - 10.0.0.150" {
		t.Errorf("both provided: got %q, want them verbatim", got)
	}
}

// TestAnchorRangeEdit: the anchored row keeps its range; every other pinned row clears its
// pin and takes its prior width as Count, so LayoutPools repacks them around the anchor.
func TestAnchorRangeEdit(t *testing.T) {
	plan := PoolPlan{
		{Kind: PoolKindFixed, Range: "10.0.0.20 - 10.0.0.29"},   // 10 wide
		{Kind: PoolKindFixed, Range: "10.0.0.235 - 10.0.0.244"}, // anchor
		{Kind: PoolKindFixed, Range: "10.0.0.40 - 10.0.0.59"},   // 20 wide
	}
	out := anchorRangeEdit(plan, 1)
	if out[1].Range != "10.0.0.235 - 10.0.0.244" {
		t.Errorf("anchor row range must be preserved, got %q", out[1].Range)
	}
	if out[0].Range != "" || out[0].Count != 10 {
		t.Errorf("neighbor 0: want cleared range + count 10, got range=%q count=%d", out[0].Range, out[0].Count)
	}
	if out[2].Range != "" || out[2].Count != 20 {
		t.Errorf("neighbor 2: want cleared range + count 20, got range=%q count=%d", out[2].Range, out[2].Count)
	}
}

// TestCanDeletePool: catch-alls are removable only in Advanced mode; other pools always.
func TestCanDeletePool(t *testing.T) {
	cases := []struct {
		class, mode string
		want        bool
	}{
		{kea.ClassNameGGOOthers, "simple", false},
		{kea.ClassNameOthers, "simple", false},
		{kea.ClassNameGGOOthers, "advanced", true},
		{"GGO-MCX", "simple", true}, // a device-class pool is always removable
	}
	for _, c := range cases {
		if got := canDeletePool(c.class, c.mode); got != c.want {
			t.Errorf("canDeletePool(%q,%q)=%v want %v", c.class, c.mode, got, c.want)
		}
	}
}

// TestGreengoCatchAllError guards the re-introduced invariant: a Simple Green-GO
// plan must keep a catch-all; Advanced and non-greengo presets are exempt.
func TestGreengoCatchAllError(t *testing.T) {
	withCA := PoolPlan{{Class: "GGO-MCX"}, {Class: kea.ClassNameGGOOthers}}
	noCA := PoolPlan{{Class: "GGO-MCX"}}

	if greengoCatchAllError("greengo", withCA, "simple") != "" {
		t.Error("plan with a catch-all should pass")
	}
	if greengoCatchAllError("greengo", noCA, "simple") == "" {
		t.Error("Simple greengo plan without a catch-all should be rejected")
	}
	if greengoCatchAllError("greengo", noCA, "advanced") != "" {
		t.Error("Advanced mode deliberately permits no catch-all")
	}
	if greengoCatchAllError("dante", noCA, "simple") != "" {
		t.Error("non-greengo presets have no catch-all requirement")
	}
}

// TestFlatPlanCountsAsCatchAll: the flat preset's single classless "All devices" pool is a
// catch-all, so a flat Green-GO scope is NOT healed with extra GGO-OTHERS/OTHERS pools
// (the reported "two additional pools"). A vendor-guarded classless pool is not a catch-all.
func TestFlatPlanCountsAsCatchAll(t *testing.T) {
	if !planHasCatchAll(flatPlan()) {
		t.Fatal("flat plan's classless 'All devices' pool must count as a catch-all")
	}
	sc := ScopeConfig{Preset: "greengo", Plan: flatPlan()}
	if got := ensureGreengoCatchAll(sc); len(got.Plan) != len(flatPlan()) {
		t.Errorf("flat greengo scope must not gain extra pools: %d -> %d", len(flatPlan()), len(got.Plan))
	}
	if planHasCatchAll(PoolPlan{{Class: "", Vendors: []string{"001f80"}}}) {
		t.Error("a vendor-guarded classless pool must NOT count as a catch-all")
	}
}

// TestEnsureGreengoCatchAll: an imported greengo plan missing its catch-alls is
// healed; non-greengo and already-OK plans are untouched.
func TestEnsureGreengoCatchAll(t *testing.T) {
	// greengo plan with only a device-class pool, no catch-all -> healed.
	in := ScopeConfig{Preset: "greengo", Plan: PoolPlan{{Class: "GGO-MCX", Kind: PoolKindFixed, Count: 10}}}
	out := ensureGreengoCatchAll(in)
	if !planHasCatchAll(out.Plan) {
		t.Error("greengo plan without catch-all should be healed")
	}
	if len(out.Plan) <= len(in.Plan) {
		t.Error("heal should append the catch-all pool(s)")
	}

	// Already has a catch-all -> unchanged.
	ok := ScopeConfig{Preset: "greengo", Plan: PoolPlan{{Class: kea.ClassNameGGOOthers, Kind: PoolKindElastic}}}
	if got := ensureGreengoCatchAll(ok); len(got.Plan) != 1 {
		t.Errorf("plan with a catch-all should be untouched, got len %d", len(got.Plan))
	}

	// Non-greengo preset -> never modified.
	dante := ScopeConfig{Preset: "dante", Plan: PoolPlan{{Class: "GGO-MCX"}}}
	if got := ensureGreengoCatchAll(dante); len(got.Plan) != 1 {
		t.Errorf("non-greengo plan should be untouched, got len %d", len(got.Plan))
	}
}
