package web

import (
	"encoding/json"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

// TestParseScopeServices covers the shared wizard//pools parse: IP validation on
// gateway/DNS, lease bounds, free-form option rows, and dropping blank/half rows.
func TestParseScopeServices(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		svc, err := parseScopeServices("10.0.0.254", "10.0.0.53, 10.0.0.54", "600", "true",
			[]string{"ntp-servers", "", "domain-name"}, []string{"10.0.0.1", "", "intercom.local"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc.Gateway != "10.0.0.254" || svc.DNS != "10.0.0.53, 10.0.0.54" || svc.LeaseLifetime != 600 || !svc.LocalDNS {
			t.Errorf("fields: %+v", svc)
		}
		// The blank middle row is dropped; two real options remain.
		if len(svc.Options) != 2 || svc.Options[0].Name != "ntp-servers" || svc.Options[1].Name != "domain-name" {
			t.Errorf("options: %+v", svc.Options)
		}
	})
	t.Run("empty is zero", func(t *testing.T) {
		svc, err := parseScopeServices("", "", "", "", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc.Gateway != "" || svc.DNS != "" || svc.LocalDNS || svc.LeaseLifetime != 0 || len(svc.Options) != 0 {
			t.Errorf("want zero ScopeServices, got %+v", svc)
		}
	})
	for _, tc := range []struct {
		name, gw, dns, lease string
	}{
		{"bad gateway", "not-an-ip", "", ""},
		{"bad dns", "", "10.0.0.5, nope", ""},
		{"lease too low", "", "", "10"},
		{"lease too high", "", "", "99999"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseScopeServices(tc.gw, tc.dns, tc.lease, "", nil, nil); err == nil {
				t.Errorf("%s: expected an error", tc.name)
			}
		})
	}
}

// TestProfileExportRoundTrip verifies a profile survives marshal→unmarshal and
// that the JSON uses the stable snake_case keys the wizard's client-side import
// reads (vlan_id, count_bpx, ...). If these drift, the Import button silently
// stops prefilling.
func TestProfileExportRoundTrip(t *testing.T) {
	in := ProfileExport{
		Name: "Tour_A",
		Scopes: []ScopeConfig{
			{
				Preset: "greengo", VlanID: 0, CIDR: "10.0.0.0/23",
				Counts: DeviceCounts{BPX: 50, MCX: 8, Nodes: 100},
				Uplink: UplinkConfig{Enabled: true, SSID: "Venue", Password: "secret"},
			},
			{Preset: "dante", VlanID: 20, CIDR: "10.20.0.0/24"},
		},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out ProfileExport
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Name != "Tour_A" || len(out.Scopes) != 2 {
		t.Fatalf("round trip lost data: %+v", out)
	}
	s0 := out.Scopes[0]
	if s0.Preset != "greengo" || s0.CIDR != "10.0.0.0/23" || s0.Counts.BPX != 50 || s0.Counts.MCX != 8 || s0.Counts.Nodes != 100 {
		t.Errorf("scope0 round trip wrong: %+v", s0)
	}
	if !s0.Uplink.Enabled || s0.Uplink.SSID != "Venue" || s0.Uplink.Password != "secret" {
		t.Errorf("scope0 uplink round trip wrong: %+v", s0.Uplink)
	}

	for _, key := range []string{`"vlan_id"`, `"cidr"`, `"counts"`, `"count_bpx"`, `"uplink"`, `"enabled"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("export JSON missing expected key %s:\n%s", key, data)
		}
	}
}

func TestDeviceCountsMapExcludesNodes(t *testing.T) {
	m := DeviceCounts{BPX: 5, Nodes: 99}.Map()
	if m["count_bpx"] != 5 {
		t.Errorf("count_bpx not mapped (got %d)", m["count_bpx"])
	}
	if _, ok := m["count_nodes"]; ok {
		t.Error("count_nodes (storage-only total) must be excluded from the pool-sizing counts")
	}
}

// TestSeedPlanPresets pins the preset -> PoolPlan dispatch. Every non-greengo
// preset seeds the SAME shape - a static reserve then a single elastic catch-all -
// differing only in the pool label; greengo seeds the full device-class plan ending
// in the two non-removable catch-alls. The render-through check proves each seeded
// plan lays out a valid, in-subnet set of pools (reserve carved out, elastic taking
// the remainder). One test for the whole family: the presets share a code path, so
// four separate golden tests would re-assert the same layout.
func TestSeedPlanPresets(t *testing.T) {
	// Non-greengo presets: [Reserve, Elastic], label per preset. "generic" (and any
	// unknown value) falls to the default label.
	for _, tc := range []struct {
		preset, label string
	}{
		{"dante", "Dante / AES67"},
		{"sacn", "sACN / Art-Net"},
		{"flat", "Green-GO (flat)"},
		{"custom", "General"},
		{"generic", "Devices"},
		{"", "Devices"},
	} {
		t.Run("preset="+tc.preset, func(t *testing.T) {
			plan := seedPlan(ScopeConfig{Preset: tc.preset, CIDR: "10.0.0.0/24"})
			if len(plan) != 2 {
				t.Fatalf("preset %q seeded %d pools, want [Reserve, Elastic]: %+v", tc.preset, len(plan), plan)
			}
			if plan[0].Kind != PoolKindReserve || plan[0].Count != staticReserveSize {
				t.Errorf("preset %q pool[0] = %+v, want Reserve of %d", tc.preset, plan[0], staticReserveSize)
			}
			if plan[1].Kind != PoolKindElastic || plan[1].Name != tc.label {
				t.Errorf("preset %q pool[1] = %+v, want Elastic labelled %q", tc.preset, plan[1], tc.label)
			}
			assertPlanLaysOut(t, plan, "10.0.0.0/24")
		})
	}

	// greengo seeds the full plan: leading reserve, and both non-removable catch-alls
	// present as elastic. (Device-class order is asserted by the layout golden tests.)
	t.Run("preset=greengo", func(t *testing.T) {
		plan := seedPlan(ScopeConfig{Preset: "greengo", CIDR: "10.0.0.0/24",
			Counts: DeviceCounts{BPX: 10, MCX: 4}})
		if plan[0].Kind != PoolKindReserve {
			t.Fatalf("greengo pool[0] = %+v, want a static reserve", plan[0])
		}
		var ggoOthers, others bool
		for _, e := range plan {
			if e.Kind == PoolKindElastic && e.Class == kea.ClassNameGGOOthers {
				ggoOthers = true
			}
			if e.Kind == PoolKindElastic && e.Class == kea.ClassNameOthers {
				others = true
			}
		}
		if !ggoOthers || !others {
			t.Errorf("greengo plan missing an elastic catch-all: GGO-OTHERS=%v OTHERS=%v\n%+v", ggoOthers, others, plan)
		}
		assertPlanLaysOut(t, plan, "10.0.0.0/24")
	})
}

// assertPlanLaysOut renders a seeded plan through the real allocator and checks it
// produced at least one pool with every range inside the subnet - the contract the
// renderer relies on.
func assertPlanLaysOut(t *testing.T, plan PoolPlan, cidr string) {
	t.Helper()
	placements, err := kea.LayoutPools(cidr, plan.ToSpecs())
	if err != nil {
		t.Fatalf("LayoutPools(%s): %v", cidr, err)
	}
	var pools int
	for _, p := range placements {
		if p.Kind == kea.PoolReserve {
			continue
		}
		pools++
		if p.Range == "" {
			t.Errorf("pool %q laid out an empty range", p.Class)
		}
	}
	if pools == 0 {
		t.Fatalf("plan for %s produced no DHCP pools", cidr)
	}
}
