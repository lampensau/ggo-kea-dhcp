package web

import (
	"strings"
	"testing"
)

// TestValidateScopeTopology covers the two invalid multi-scope topologies that pass
// kea -t but silently misbehave: a duplicate VLAN ID (one segment never serves) and
// overlapping CIDRs (a reservation misfiled under the wrong subnet). Both apply
// (beginApply) and switch (beginSwitch) run this before render.
func TestValidateScopeTopology(t *testing.T) {
	cases := []struct {
		name    string
		scopes  []ScopeConfig
		wantErr string // substring; "" means valid
	}{
		{
			name: "distinct VLANs and subnets ok",
			scopes: []ScopeConfig{
				{VlanID: 0, CIDR: "10.0.0.0/24"},
				{VlanID: 10, CIDR: "10.0.10.0/24"},
				{VlanID: 20, CIDR: "10.0.20.0/24"},
			},
		},
		{
			name: "single scope ok",
			scopes: []ScopeConfig{
				{VlanID: 0, CIDR: "192.168.1.0/24"},
			},
		},
		{
			name: "duplicate tagged VLAN rejected",
			scopes: []ScopeConfig{
				{VlanID: 10, CIDR: "10.0.10.0/24"},
				{VlanID: 10, CIDR: "10.0.20.0/24"},
			},
			wantErr: "VLAN 10 is used by more than one scope",
		},
		{
			name: "two untagged scopes rejected",
			scopes: []ScopeConfig{
				{VlanID: 0, CIDR: "10.0.0.0/24"},
				{VlanID: 0, CIDR: "10.0.1.0/24"},
			},
			wantErr: "Only one untagged network scope",
		},
		{
			name: "identical CIDRs on different VLANs rejected",
			scopes: []ScopeConfig{
				{VlanID: 10, CIDR: "10.0.0.0/24"},
				{VlanID: 20, CIDR: "10.0.0.0/24"},
			},
			wantErr: "overlap",
		},
		{
			name: "supernet containing a subnet rejected",
			scopes: []ScopeConfig{
				{VlanID: 10, CIDR: "10.0.0.0/16"},
				{VlanID: 20, CIDR: "10.0.5.0/24"},
			},
			wantErr: "overlap",
		},
		{
			name: "out-of-range VLAN rejected (switch-path guard)",
			scopes: []ScopeConfig{
				{VlanID: 9999, CIDR: "10.0.0.0/24"},
			},
			wantErr: "out of range",
		},
		{
			name: "invalid CIDR rejected",
			scopes: []ScopeConfig{
				{VlanID: 10, CIDR: "not-a-cidr"},
			},
			wantErr: "not a valid CIDR",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateScopeTopology(tc.scopes)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
