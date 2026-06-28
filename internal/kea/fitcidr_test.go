package kea

import "testing"

func TestFitCIDRWidensOnOverflow(t *testing.T) {
	// Fixed pools summing > a /24's usable space must widen the CIDR.
	specs := []PoolSpec{
		{Class: "GGO-MCX-D", Kind: PoolFixed, Size: 200},
		{Class: "GGO-WP-X", Kind: PoolFixed, Size: 200},
		{Class: "OTHERS", Kind: PoolElastic, Weight: 1},
	}
	got := FitCIDR("10.0.0.0/24", specs)
	if got == "10.0.0.0/24" {
		t.Fatalf("expected widening, got %q", got)
	}
	if _, err := LayoutPools(got, specs); err != nil {
		t.Fatalf("fitted CIDR %q still does not fit: %v", got, err)
	}
	// A plan that already fits is returned unchanged (idempotent).
	small := []PoolSpec{{Class: "GGO-BPX", Kind: PoolFixed, Size: 10}, {Class: "OTHERS", Kind: PoolElastic, Weight: 1}}
	if got := FitCIDR("10.0.0.0/24", small); got != "10.0.0.0/24" {
		t.Errorf("fitting plan should stay /24, got %q", got)
	}
}
