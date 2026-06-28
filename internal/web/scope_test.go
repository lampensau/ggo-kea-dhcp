package web

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestParseScopeServices covers the shared wizard//pools parse: IP validation on
// gateway/DNS, lease bounds, free-form option rows, and dropping blank/half rows.
func TestParseScopeServices(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		svc, err := parseScopeServices("10.0.0.254", "10.0.0.53, 10.0.0.54", "600",
			[]string{"ntp-servers", "", "domain-name"}, []string{"10.0.0.1", "", "intercom.local"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc.Gateway != "10.0.0.254" || svc.DNS != "10.0.0.53, 10.0.0.54" || svc.LeaseLifetime != 600 {
			t.Errorf("fields: %+v", svc)
		}
		// The blank middle row is dropped; two real options remain.
		if len(svc.Options) != 2 || svc.Options[0].Name != "ntp-servers" || svc.Options[1].Name != "domain-name" {
			t.Errorf("options: %+v", svc.Options)
		}
	})
	t.Run("empty is zero", func(t *testing.T) {
		svc, err := parseScopeServices("", "", "", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc.Gateway != "" || svc.DNS != "" || svc.LeaseLifetime != 0 || len(svc.Options) != 0 {
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
			if _, err := parseScopeServices(tc.gw, tc.dns, tc.lease, nil, nil); err == nil {
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
