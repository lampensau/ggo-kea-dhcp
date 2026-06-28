package web

import (
	"encoding/json"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

// TestSeedPlanGreengo verifies the seed model: the device classes are seeded as
// Fixed pools in the operator-facing order (user stations, antennas, interfaces),
// every forecast type included; GGO-OTHERS and OTHERS are both Elastic catch-alls
// that split the subnet remainder (GGO-OTHERS weighted heavier so unconfigured
// Green-GO gear has room).
func TestSeedPlanGreengo(t *testing.T) {
	sc := ScopeConfig{Preset: "greengo", CIDR: "10.0.0.0/24", Counts: DeviceCounts{
		BPX: 20, MCX: 10, MCD: 4, Interface: 4, WPX: 8, Bridge: 2, WAA: 14, Beacon: 2, Stride: 3, Others: 18,
	}}
	plan := seedPlan(sc)

	// The operator-facing default order: Static reserve, then user stations led by
	// the elastic Beltpacks pool, then antennas, then interfaces, then the two
	// catch-alls (Green-GO Fixed, non-Green-GO Elastic). All counts above are > 0,
	// so every device class is seeded.
	wantOrder := []struct{ class, kind string }{
		{"", PoolKindReserve},                     // Static reserve
		{"GGO-BPX", PoolKindFixed},                // user stations: Beltpacks
		{"GGO-MCX-D", PoolKindFixed},              //   Multi-channel
		{"GGO-MCD-MCR", PoolKindFixed},            //   Desktop / rack
		{"GGO-WP-X", PoolKindFixed},               //   Wall panels
		{"GGO-WAA", PoolKindFixed},                // antennas: Active antennas
		{"GGO-STRIDE", PoolKindFixed},             //   STRIDE antennas
		{"GGO-RDX-SI-BEACON", PoolKindFixed},      // interfaces: Radio / SI / beacon
		{"GGO-INTERFACE-Q4WR", PoolKindFixed},     //   Interfaces
		{"GGO-BRIDGE-DANTEX", PoolKindFixed},      //   Bridges / Dante
		{kea.ClassNameGGOOthers, PoolKindElastic}, // Green-GO catch-all (elastic)
		{kea.ClassNameOthers, PoolKindElastic},    // non-Green-GO backstop
	}
	if len(plan) != len(wantOrder) {
		t.Fatalf("got %d plan entries, want %d: %+v", len(plan), len(wantOrder), plan)
	}
	for i, w := range wantOrder {
		if plan[i].Class != w.class || plan[i].Kind != w.kind {
			t.Errorf("plan[%d] = {class %q, kind %q}, want {class %q, kind %q}", i, plan[i].Class, plan[i].Kind, w.class, w.kind)
		}
	}

	// The reordered plan must lay out cleanly (no error, no stranded space):
	// Beltpacks leads at .20, the non-Green-GO backstop ends at the last usable .254.
	got, err := kea.LayoutPools("10.0.0.0/24", plan.ToSpecs())
	if err != nil {
		t.Fatalf("LayoutPools: %v", err)
	}
	ranges := map[string]string{}
	for _, p := range got {
		ranges[p.Class] = p.Range
	}
	if lo, _, _ := strings.Cut(ranges["GGO-BPX"], " - "); lo != "10.0.0.20" {
		t.Errorf("Beltpacks (leading fixed pool) starts at %q, want 10.0.0.20", lo)
	}
	if _, hi, _ := strings.Cut(ranges["OTHERS"], " - "); hi != "10.0.0.254" {
		t.Errorf("non-Green-GO backstop ends at %q, want 10.0.0.254", hi)
	}
}

// TestPoolPlan_JSONRoundTrip confirms the plan persists and reloads unchanged.
func TestPoolPlan_JSONRoundTrip(t *testing.T) {
	in := PoolPlan{
		{Kind: PoolKindReserve, Name: "Static reserve", Count: 18},
		{Kind: PoolKindFixed, Class: "GGO-WP-X", Sizing: "auto", Count: 8, Icon: "wpx"},
		{Kind: PoolKindFixed, Name: "Lighting", Sizing: "explicit", Count: 12, Range: "10.0.0.40 - 10.0.0.51", Vendors: []string{"001fce", "0050c2"}, Icon: "sliders-horizontal"},
		{Kind: PoolKindElastic, Class: "GGO-BPX", Weight: 3},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out PoolPlan
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round-trip length %d != %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Kind != in[i].Kind || out[i].Class != in[i].Class || out[i].Name != in[i].Name ||
			out[i].Sizing != in[i].Sizing || out[i].Count != in[i].Count || out[i].Range != in[i].Range ||
			out[i].Weight != in[i].Weight || out[i].Icon != in[i].Icon || len(out[i].Vendors) != len(in[i].Vendors) {
			t.Errorf("entry %d round-tripped to %+v, want %+v", i, out[i], in[i])
		}
	}
}
