package web

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// formRequest builds a request whose Form is pre-populated, so FormValue reads
// these values directly without a body parse.
func formRequest(vals url.Values) *http.Request {
	return &http.Request{Form: vals}
}

// TestParseSetupScopes covers the Datastar editor's path: the plan rides to apply
// as scopes[i][pool][n][...] fields, which parseSetupScopes reads into sc.Plan
// (counts now live inside the plan's Fixed entries, not as scopes[i][count_*]).
func TestParseSetupScopes(t *testing.T) {
	v := url.Values{}
	v.Set("scopes[0][preset]", "greengo")
	v.Set("scopes[0][vlan]", "10")
	v.Set("scopes[0][cidr]", "10.0.0.1/24")
	v.Set("scopes[0][uplink]", "true") // per-scope toggle only; SSID/pass are box-level now
	// A three-row plan posted by the editor: a Fixed BPX pool of 5, then the two
	// required catch-alls (GGO-OTHERS Fixed/auto, OTHERS elastic).
	v.Set("scopes[0][pool][0][kind]", "fixed")
	v.Set("scopes[0][pool][0][class]", "GGO-BPX")
	v.Set("scopes[0][pool][0][sizing]", "explicit")
	v.Set("scopes[0][pool][0][count]", "5")
	v.Set("scopes[0][pool][1][kind]", "fixed")
	v.Set("scopes[0][pool][1][class]", "GGO-OTHERS")
	v.Set("scopes[0][pool][1][sizing]", "auto")
	v.Set("scopes[0][pool][2][kind]", "elastic")
	v.Set("scopes[0][pool][2][class]", "OTHERS")
	v.Set("scopes[0][pool][2][weight]", "1")

	scopes, err := parseSetupScopes(formRequest(v))
	if err != nil {
		t.Fatalf("parseSetupScopes: %v", err)
	}
	if len(scopes) != 1 {
		t.Fatalf("got %d scopes want 1", len(scopes))
	}
	sc := scopes[0]
	if sc.Preset != "greengo" || sc.VlanID != 10 || sc.CIDR != "10.0.0.1/24" || !sc.Uplink.Enabled {
		t.Errorf("parsed scope wrong: %+v", sc)
	}
	if len(sc.Plan) != 3 {
		t.Fatalf("got %d plan entries want 3: %+v", len(sc.Plan), sc.Plan)
	}
	if sc.Plan[0].Kind != PoolKindFixed || sc.Plan[0].Class != "GGO-BPX" || sc.Plan[0].Count != 5 {
		t.Errorf("plan[0] wrong: %+v", sc.Plan[0])
	}
	if sc.Plan[1].Kind != PoolKindFixed || sc.Plan[1].Class != "GGO-OTHERS" {
		t.Errorf("plan[1] wrong: %+v", sc.Plan[1])
	}
	if sc.Plan[2].Kind != PoolKindElastic || sc.Plan[2].Class != "OTHERS" {
		t.Errorf("plan[2] wrong: %+v", sc.Plan[2])
	}
}

// TestParseSetupScopesSeedsWhenNoPlan verifies the fallback: a scope with no
// posted pool fields gets a seeded plan (an untouched wizard scope).
func TestParseSetupScopesSeedsWhenNoPlan(t *testing.T) {
	v := url.Values{}
	v.Set("scopes[0][preset]", "greengo")
	v.Set("scopes[0][vlan]", "0")
	v.Set("scopes[0][cidr]", "10.0.0.1/24")

	scopes, err := parseSetupScopes(formRequest(v))
	if err != nil {
		t.Fatalf("parseSetupScopes: %v", err)
	}
	if len(scopes[0].Plan) == 0 {
		t.Errorf("expected a seeded plan, got none")
	}
}

func TestParseSetupScopesRequiresOne(t *testing.T) {
	if _, err := parseSetupScopes(formRequest(url.Values{})); err == nil {
		t.Error("expected error for zero scopes")
	}
}

func TestParseSetupScopesRejectsMultipleUntagged(t *testing.T) {
	v := url.Values{}
	v.Set("scopes[0][preset]", "greengo")
	v.Set("scopes[0][vlan]", "0")
	v.Set("scopes[0][cidr]", "10.0.0.1/24")
	v.Set("scopes[1][preset]", "dante")
	v.Set("scopes[1][vlan]", "0")
	v.Set("scopes[1][cidr]", "10.0.1.1/24")
	if _, err := parseSetupScopes(formRequest(v)); err == nil {
		t.Error("expected error for two untagged scopes")
	}
}

func TestParseSetupScopesRejectsOverCap(t *testing.T) {
	v := url.Values{}
	for i := 0; i <= maxScopes; i++ { // maxScopes+1 actual scopes
		v.Set(fmt.Sprintf("scopes[%d][preset]", i), "greengo")
		v.Set(fmt.Sprintf("scopes[%d][cidr]", i), "10.0.0.0/24")
	}
	if _, err := parseSetupScopes(formRequest(v)); err == nil {
		t.Error("expected error for over-cap submission")
	}
}

// TestParseSetupScopesToleratesGaps: removing a middle scope (or duplicating) leaves a
// hole in the scopes[i] indices (e.g. 0,2). Both surviving scopes must still be parsed in
// order - not just the first (the "only the first scope is created" bug).
func TestParseSetupScopesToleratesGaps(t *testing.T) {
	v := url.Values{}
	v.Set("scopes[0][preset]", "greengo")
	v.Set("scopes[0][cidr]", "10.0.0.0/24")
	v.Set("scopes[2][preset]", "dante")
	v.Set("scopes[2][vlan]", "20")
	v.Set("scopes[2][cidr]", "10.0.20.0/24")
	scopes, err := parseSetupScopes(formRequest(v))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("got %d scopes, want 2 (gap-tolerant)", len(scopes))
	}
	if scopes[0].Preset != "greengo" || scopes[1].Preset != "dante" {
		t.Errorf("scopes parsed out of order: %q, %q", scopes[0].Preset, scopes[1].Preset)
	}
}

func TestBuildRenderScopesGatewayPrefersUntagged(t *testing.T) {
	scopes := []ScopeConfig{
		{Preset: "dante", VlanID: 10, CIDR: "10.0.1.1/24"},     // tagged, parsed first
		{Preset: "greengo", VlanID: 0, CIDR: "192.168.0.1/24"}, // untagged wins
	}
	render, gw := buildRenderScopes(scopes, true)
	if len(render) != 2 {
		t.Fatalf("got %d render scopes want 2", len(render))
	}
	if gw != "192.168.0.1" {
		t.Errorf("gateway = %q want 192.168.0.1 (untagged scope)", gw)
	}
}

// fakeRogueProbe satisfies rogueProber without a capture socket.
type fakeRogueProbe struct {
	ip, mac string
	found   bool
}

func (f *fakeRogueProbe) Start(string) {}
func (f *fakeRogueProbe) Stop()        {}
func (f *fakeRogueProbe) Server() (string, string, bool) {
	return f.ip, f.mac, f.found
}

// TestShieldStatus covers the wizard badge's three states: no carrier stays
// Suspended regardless of the probe, a quiet probe (or none - the ACTIVE edit
// page) yields Active, and a foreign DHCP answer flips to Detected naming the
// server's IP.
func TestShieldStatus(t *testing.T) {
	s := &Server{}

	if st, d := s.shieldStatus("Suspended"); st != "Suspended" || d != "" {
		t.Errorf("no carrier: got %q/%q, want Suspended with no detail", st, d)
	}
	if st, d := s.shieldStatus("Active"); st != "Active" || d != "" {
		t.Errorf("no probe: got %q/%q, want Active", st, d)
	}

	s.rogueProbe = &fakeRogueProbe{}
	if st, d := s.shieldStatus("Active"); st != "Active" || d != "" {
		t.Errorf("quiet probe: got %q/%q, want Active", st, d)
	}

	s.rogueProbe = &fakeRogueProbe{ip: "10.0.0.250", mac: "00:11:22:33:44:55", found: true}
	if st, d := s.shieldStatus("Active"); st != "Detected" || d != "10.0.0.250" {
		t.Errorf("foreign OFFER: got %q/%q, want Detected/10.0.0.250", st, d)
	}
	// Carrier down wins even while a server is latched (no link = nothing answering us).
	if st, d := s.shieldStatus("Suspended"); st != "Suspended" || d != "" {
		t.Errorf("no carrier with latched server: got %q/%q, want Suspended", st, d)
	}
}
