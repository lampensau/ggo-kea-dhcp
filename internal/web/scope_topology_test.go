package web

import (
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/db"
)

// TestRestoreRejectsBadTopology proves restore() runs the same topology guard as
// beginApply/beginSwitch, so a hand-edited/cross-version bundle carrying a duplicate
// VLAN can't be ingested. Restore is one transaction, so the rejection must leave the
// database untouched (rolled back), not half-applied.
func TestRestoreRejectsBadTopology(t *testing.T) {
	s, _ := newTestServer(t)

	// A pre-existing good profile that must survive the failed restore.
	if _, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('Existing', 1)"); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	var schema int
	_ = s.sqlite.QueryRow("PRAGMA user_version;").Scan(&schema)
	b := &Backup{
		Format: backupFormat, AppSchema: schema, Lifecycle: db.StateActive,
		Profiles: []BackupProfile{{
			Name: "Bad", Active: true,
			Scopes: []ScopeConfig{
				{VlanID: 10, CIDR: "10.0.10.0/24"},
				{VlanID: 10, CIDR: "10.0.20.0/24"}, // duplicate VLAN
			},
		}},
	}
	lifecycle, err := s.restore(b, map[string]bool{"profiles": true})
	if err == nil {
		t.Fatal("expected restore to reject the duplicate-VLAN bundle, got nil error")
	}
	if lifecycle != "" {
		t.Errorf("hard-failed restore must return an empty lifecycle, got %q", lifecycle)
	}
	if !strings.Contains(err.Error(), "VLAN 10") {
		t.Errorf("error should name the offending VLAN, got: %v", err)
	}
	// Rollback: the pre-existing profile is still there, the bad one is not.
	var name string
	if err := s.sqlite.QueryRow("SELECT name FROM profiles").Scan(&name); err != nil {
		t.Fatalf("read profiles after rollback: %v", err)
	}
	if name != "Existing" {
		t.Errorf("restore should have rolled back; profiles table = %q, want only Existing", name)
	}
}

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
