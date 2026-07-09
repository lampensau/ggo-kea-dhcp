package web

import (
	"encoding/json"
	"strings"
	"testing"
)

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
