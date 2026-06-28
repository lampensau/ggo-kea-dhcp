package kea

import "testing"

// TestGenerateElasticPools_Golden pins the EXACT current greengo elastic layout
// for a representative scope. Phase 2 generalizes the allocator to a per-pool
// Fixed/Elastic(weight)/Reserve model; the default greengo configuration (every
// device class Fixed = count×headroom, BPX the single Elastic remainder, in
// DeviceClasses order from .20) MUST keep producing byte-identical ranges. This
// golden is the regression guard for that refactor - if it changes, the default
// behavior changed and that must be intentional.
func TestGenerateElasticPools_Golden(t *testing.T) {
	counts := map[string]int{
		"count_mcx": 10, "count_mcd": 4, "count_interface": 4, "count_wpx": 8,
		"count_bridge": 2, "count_waa": 14, "count_beacon": 2, "count_stride": 3, "count_others": 18,
	}
	want := []PoolConfig{
		{ClientClass: "GGO-MCX-D", Range: "10.0.0.20 - 10.0.0.59"},
		{ClientClass: "GGO-MCD-MCR", Range: "10.0.0.60 - 10.0.0.67"},
		{ClientClass: "GGO-WP-X", Range: "10.0.0.68 - 10.0.0.83"},
		{ClientClass: "GGO-STRIDE", Range: "10.0.0.84 - 10.0.0.89"},
		{ClientClass: "GGO-WAA", Range: "10.0.0.90 - 10.0.0.117"},
		{ClientClass: "GGO-RDX-SI-BEACON", Range: "10.0.0.118 - 10.0.0.122"},
		{ClientClass: "GGO-INTERFACE-Q4WR", Range: "10.0.0.123 - 10.0.0.130"},
		{ClientClass: "GGO-BRIDGE-DANTEX", Range: "10.0.0.131 - 10.0.0.135"},
		{ClientClass: "GGO-SWITCH", Range: "10.0.0.136 - 10.0.0.140"}, // count 0 → minPool floor
		{ClientClass: "GGO-OTHERS", Range: "10.0.0.141 - 10.0.0.150"},
		{ClientClass: "OTHERS", Range: "10.0.0.151 - 10.0.0.186"},
		{ClientClass: "GGO-BPX", Range: "10.0.0.187 - 10.0.0.254"},
	}
	got, err := GenerateElasticPools("10.0.0.0/24", counts)
	if err != nil {
		t.Fatalf("GenerateElasticPools: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d pools, want %d:\n%+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].ClientClass != want[i].ClientClass || got[i].Range != want[i].Range {
			t.Errorf("pool[%d] = {%q, %q}, want {%q, %q}",
				i, got[i].ClientClass, got[i].Range, want[i].ClientClass, want[i].Range)
		}
	}
}
