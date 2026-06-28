package kea

import "testing"

// dhcpRanges drops Reserve placements (the renderer emits no Kea pool for them)
// and returns the remaining class→range pairs in order.
func dhcpRanges(ps []PoolPlacement) []PoolConfig {
	var out []PoolConfig
	for _, p := range ps {
		if p.Kind == PoolReserve {
			continue
		}
		out = append(out, PoolConfig{ClientClass: p.Class, Range: p.Range})
	}
	return out
}

// TestLayoutPools_MatchesGoldenElastic proves the generalized allocator reproduces
// the legacy greengo elastic layout byte-for-byte when fed the equivalent specs:
// a leading static Reserve (.2–.19), each device class Fixed at its count×headroom
// size, the two catch-alls, and BPX as the single Elastic remainder - in order.
// The expected ranges are identical to TestGenerateElasticPools_Golden.
func TestLayoutPools_MatchesGoldenElastic(t *testing.T) {
	specs := []PoolSpec{
		{Kind: PoolReserve, Size: 18}, // static reserve .2 - .19
		{Class: "GGO-MCX-D", Kind: PoolFixed, Size: 40},
		{Class: "GGO-MCD-MCR", Kind: PoolFixed, Size: 8},
		{Class: "GGO-INTERFACE-Q4WR", Kind: PoolFixed, Size: 8},
		{Class: "GGO-WP-X", Kind: PoolFixed, Size: 16},
		{Class: "GGO-BRIDGE-DANTEX", Kind: PoolFixed, Size: 5},
		{Class: "GGO-WAA", Kind: PoolFixed, Size: 28},
		{Class: "GGO-RDX-SI-BEACON", Kind: PoolFixed, Size: 5},
		{Class: "GGO-STRIDE", Kind: PoolFixed, Size: 6},
		{Class: "GGO-OTHERS", Kind: PoolFixed, Size: 10},
		{Class: "OTHERS", Kind: PoolFixed, Size: 36},
		{Class: "GGO-BPX", Kind: PoolElastic, Weight: 1},
	}
	want := []PoolConfig{
		{ClientClass: "GGO-MCX-D", Range: "10.0.0.20 - 10.0.0.59"},
		{ClientClass: "GGO-MCD-MCR", Range: "10.0.0.60 - 10.0.0.67"},
		{ClientClass: "GGO-INTERFACE-Q4WR", Range: "10.0.0.68 - 10.0.0.75"},
		{ClientClass: "GGO-WP-X", Range: "10.0.0.76 - 10.0.0.91"},
		{ClientClass: "GGO-BRIDGE-DANTEX", Range: "10.0.0.92 - 10.0.0.96"},
		{ClientClass: "GGO-WAA", Range: "10.0.0.97 - 10.0.0.124"},
		{ClientClass: "GGO-RDX-SI-BEACON", Range: "10.0.0.125 - 10.0.0.129"},
		{ClientClass: "GGO-STRIDE", Range: "10.0.0.130 - 10.0.0.135"},
		{ClientClass: "GGO-OTHERS", Range: "10.0.0.136 - 10.0.0.145"},
		{ClientClass: "OTHERS", Range: "10.0.0.146 - 10.0.0.181"},
		{ClientClass: "GGO-BPX", Range: "10.0.0.182 - 10.0.0.254"},
	}
	got, err := LayoutPools("10.0.0.0/24", specs)
	if err != nil {
		t.Fatalf("LayoutPools: %v", err)
	}
	assertPools(t, dhcpRanges(got), want)
}

func TestLayoutPools_WeightedMultiElastic(t *testing.T) {
	// /24 usable-for-pools = .2..254 = 253; reserve 18 → remainder 235.
	// w3 → 235*3/4 = 176, w1 → 235*1/4 = 58 (sum 234); leftover 1 → largest weight.
	specs := []PoolSpec{
		{Kind: PoolReserve, Size: 18},
		{Class: "A", Kind: PoolElastic, Weight: 3},
		{Class: "B", Kind: PoolElastic, Weight: 1},
	}
	got, err := LayoutPools("10.0.0.0/24", specs)
	if err != nil {
		t.Fatalf("LayoutPools: %v", err)
	}
	want := []PoolConfig{
		{ClientClass: "A", Range: "10.0.0.20 - 10.0.0.196"},  // 177 (176 + leftover 1)
		{ClientClass: "B", Range: "10.0.0.197 - 10.0.0.254"}, // 58
	}
	assertPools(t, dhcpRanges(got), want)
}

func TestLayoutPools_NoElasticLeavesFreeReserve(t *testing.T) {
	specs := []PoolSpec{
		{Kind: PoolReserve, Size: 18},
		{Class: "A", Kind: PoolFixed, Size: 10},
		{Class: "B", Kind: PoolFixed, Size: 20},
		{Class: "C", Kind: PoolFixed, Size: 30},
	}
	got, err := LayoutPools("10.0.0.0/24", specs)
	if err != nil {
		t.Fatalf("LayoutPools: %v", err)
	}
	want := []PoolConfig{
		{ClientClass: "A", Range: "10.0.0.20 - 10.0.0.29"},
		{ClientClass: "B", Range: "10.0.0.30 - 10.0.0.49"},
		{ClientClass: "C", Range: "10.0.0.50 - 10.0.0.79"},
	}
	assertPools(t, dhcpRanges(got), want)
	// Nothing fills to .254 - the leftover .80–.254 stays free.
	last := got[len(got)-1]
	if last.Range != "10.0.0.50 - 10.0.0.79" {
		t.Errorf("expected last pool to end at .79 (free reserve above), got %q", last.Range)
	}
}

func TestLayoutPools_OrderControlsPlacement(t *testing.T) {
	// Elastic placed FIRST should take the low addresses ("BPX on top").
	specs := []PoolSpec{
		{Class: "FILL", Kind: PoolElastic, Weight: 1},
		{Class: "A", Kind: PoolFixed, Size: 10},
		{Kind: PoolReserve, Size: 5},
	}
	got, err := LayoutPools("10.0.0.0/24", specs)
	if err != nil {
		t.Fatalf("LayoutPools: %v", err)
	}
	// remainder = 253 - 10 - 5 = 238 → FILL .2..239, A .240..249, reserve .250..254.
	if got[0].Range != "10.0.0.2 - 10.0.0.239" {
		t.Errorf("elastic-first should start at .2, got %q", got[0].Range)
	}
	if got[1].Range != "10.0.0.240 - 10.0.0.249" {
		t.Errorf("fixed after elastic = %q, want 10.0.0.240 - 10.0.0.249", got[1].Range)
	}
	if got[2].Kind != PoolReserve || got[2].Range != "10.0.0.250 - 10.0.0.254" {
		t.Errorf("reserve last = %q, want 10.0.0.250 - 10.0.0.254", got[2].Range)
	}
}

func TestLayoutPools_TooSmallErrors(t *testing.T) {
	// /28 = 16 addrs, usable-for-pools .2..14 = 13; fixed demand 20 > 13.
	_, err := LayoutPools("10.0.0.0/28", []PoolSpec{
		{Class: "A", Kind: PoolFixed, Size: 20},
	})
	if err == nil {
		t.Fatal("expected an error when fixed pools exceed the subnet")
	}
}

// TestSizeForClass_IsCountFlooredNoHeadroom pins the auto-sizing helper to the
// WYSIWYG model: a pool's size is its forecast count, floored to the class minimum
// (5 normal, 10 catch-all). No per-class headroom multiplier is applied.
func TestSizeForClass_IsCountFlooredNoHeadroom(t *testing.T) {
	cases := []struct {
		class string
		count int
		want  int
	}{
		{"GGO-MCX-D", 10, 10},        // no x4 headroom anymore
		{"GGO-MCD-MCR", 4, 5},        // floored to 5
		{"GGO-INTERFACE-Q4WR", 4, 5}, // floored to 5
		{"GGO-WP-X", 8, 8},
		{"GGO-BRIDGE-DANTEX", 2, 5}, // floored to 5
		{"GGO-WAA", 14, 14},
		{"GGO-RDX-SI-BEACON", 2, 5},
		{"GGO-STRIDE", 3, 5},   // floored to 5
		{"GGO-OTHERS", 0, 10},  // catch-all floor
		{"GGO-OTHERS", 48, 48}, // grows with the count (no longer pinned to 10)
		{"OTHERS", 18, 18},
	}
	for _, c := range cases {
		if got := SizeForClass(c.class, c.count); got != c.want {
			t.Errorf("SizeForClass(%q, %d) = %d, want %d", c.class, c.count, got, c.want)
		}
	}
}

func TestLayoutPools_AdvancedPinnedThenElasticFills(t *testing.T) {
	// Advanced: a reserve + a Fixed pool pinned at exact ranges, BPX elastic fills
	// the trailing gap. The reserve is dropped from the DHCP output.
	specs := []PoolSpec{
		{Kind: PoolReserve, Range: "10.0.0.2 - 10.0.0.19"},
		{Class: "GGO-WP-X", Kind: PoolFixed, Range: "10.0.0.20 - 10.0.0.59"},
		{Class: "GGO-BPX", Kind: PoolElastic, Weight: 1},
	}
	got, err := LayoutPools("10.0.0.0/24", specs)
	if err != nil {
		t.Fatalf("LayoutPools: %v", err)
	}
	want := []PoolConfig{
		{ClientClass: "GGO-WP-X", Range: "10.0.0.20 - 10.0.0.59"},
		{ClientClass: "GGO-BPX", Range: "10.0.0.60 - 10.0.0.254"},
	}
	assertPools(t, dhcpRanges(got), want)
}

func TestLayoutPools_ElasticCapsToLargestGapWhenFragmented(t *testing.T) {
	// Pins fragment the space into two gaps; the single elastic can only occupy one
	// contiguous range, so it caps to the largest gap (the other stays free).
	specs := []PoolSpec{
		{Kind: PoolReserve, Range: "10.0.0.100 - 10.0.0.119"}, // splits the space
		{Class: "FILL", Kind: PoolElastic, Weight: 1},
	}
	got, err := LayoutPools("10.0.0.0/24", specs)
	if err != nil {
		t.Fatalf("LayoutPools: %v", err)
	}
	// gaps: .2–.99 (98) and .120–.254 (135) → elastic takes the larger (.120–.254).
	want := []PoolConfig{{ClientClass: "FILL", Range: "10.0.0.120 - 10.0.0.254"}}
	assertPools(t, dhcpRanges(got), want)
}

func TestLayoutPools_PinnedOverlapErrors(t *testing.T) {
	_, err := LayoutPools("10.0.0.0/24", []PoolSpec{
		{Class: "A", Kind: PoolFixed, Range: "10.0.0.10 - 10.0.0.20"},
		{Class: "B", Kind: PoolFixed, Range: "10.0.0.15 - 10.0.0.25"},
	})
	if err == nil {
		t.Fatal("expected an error for overlapping pinned ranges")
	}
}

func TestLayoutPools_PinOutOfBoundsErrors(t *testing.T) {
	// .1 is the gateway (below poolLo) → out of the usable pool range.
	_, err := LayoutPools("10.0.0.0/24", []PoolSpec{
		{Class: "A", Kind: PoolFixed, Range: "10.0.0.1 - 10.0.0.10"},
	})
	if err == nil {
		t.Fatal("expected an error for a pin outside the usable subnet")
	}
}

func TestLayoutPools_UnpinnedFixedThatFitsNoGapErrors(t *testing.T) {
	// /26 = 64 addrs (.2–.62 usable); a reserve pin in the middle leaves gaps of 28
	// and 22; an unpinned Fixed of 40 fits neither → error (exact size matters).
	_, err := LayoutPools("10.0.0.0/26", []PoolSpec{
		{Kind: PoolReserve, Range: "10.0.0.30 - 10.0.0.40"},
		{Class: "BIG", Kind: PoolFixed, Size: 40},
	})
	if err == nil {
		t.Fatal("expected an error when an unpinned fixed pool fits no gap")
	}
}

func assertPools(t *testing.T, got, want []PoolConfig) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d pools, want %d:\n got=%+v\nwant=%+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i].ClientClass != want[i].ClientClass || got[i].Range != want[i].Range {
			t.Errorf("pool[%d] = {%q, %q}, want {%q, %q}",
				i, got[i].ClientClass, got[i].Range, want[i].ClientClass, want[i].Range)
		}
	}
}
