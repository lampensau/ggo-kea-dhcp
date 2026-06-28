package web

import (
	"testing"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/netmon"

	"golang.org/x/net/bpf"
)

// TestBuildNetmonSpecs_VLANPlacement guards H2: the VLAN-reality detector attaches
// only to a raw eth0 monitor, never to an eth0.<vid> sub-interface (where tags are
// stripped), and a pure-trunk profile synthesizes a raw eth0 VLAN-only monitor.
func TestBuildNetmonSpecs_VLANPlacement(t *testing.T) {
	s, _ := newTestServer(t)

	// Mixed profile: one untagged eth0 scope + one tagged scope.
	mixed := s.buildNetmonSpecs([]ScopeConfig{
		{Preset: "greengo", VlanID: 0, CIDR: "10.0.0.0/24"},
		{Preset: "dante", VlanID: 20, CIDR: "10.0.20.0/24"},
	})
	byIface := map[string]netmon.Spec{}
	for _, sp := range mixed {
		byIface[sp.Iface] = sp
	}
	if !byIface["eth0"].WatchVLANs {
		t.Error("untagged eth0 monitor should watch VLANs")
	}
	if byIface["eth0.20"].WatchVLANs {
		t.Error("eth0.20 sub-interface monitor must NOT watch VLANs (tags are stripped there)")
	}
	if _, ok := byIface["eth0.20"]; !ok || byIface["eth0.20"].RawTrunkOnly {
		t.Error("eth0.20 should be a normal served monitor")
	}

	// Pure-trunk profile: every scope tagged → synthesize a raw eth0 VLAN monitor.
	trunk := s.buildNetmonSpecs([]ScopeConfig{
		{Preset: "greengo", VlanID: 10, CIDR: "10.0.10.0/24"},
		{Preset: "dante", VlanID: 20, CIDR: "10.0.20.0/24"},
	})
	var raw *netmon.Spec
	for i := range trunk {
		if trunk[i].Iface == "eth0" {
			raw = &trunk[i]
		}
		if trunk[i].Iface != "eth0" && trunk[i].WatchVLANs {
			t.Errorf("tagged monitor %s must not watch VLANs", trunk[i].Iface)
		}
	}
	if raw == nil || !raw.RawTrunkOnly {
		t.Fatal("pure-trunk profile should synthesize a RawTrunkOnly eth0 VLAN monitor")
	}
	if len(raw.ConfiguredVIDs) != 2 {
		t.Errorf("synthesized raw monitor should carry all configured VIDs, got %v", raw.ConfiguredVIDs)
	}
}

// fakeNetmon swaps the server's monitor for one backed by a FakeSniffer so the
// state-gate test never opens a real AF_PACKET socket.
func fakeNetmon(s *Server) {
	openFn := func(string, bool, []bpf.RawInstruction) (netmon.Sniffer, error) {
		return netmon.NewFakeSniffer(), nil
	}
	s.netmon = netmon.NewMonitorManagerWithSniffer(openFn, s.sqlite.GetState, nil)
}

func TestNetmon_ACTIVEOnlyStateGate(t *testing.T) {
	s, _ := newTestServer(t)
	fakeNetmon(s)
	defer s.netmon.Stop()
	_ = seedActiveProfile(t, s)

	// reconcileActive starts a monitor for the served eth0 scope.
	_ = s.reconcileActive(ModeConverge, 0)
	if got := s.netmon.Running(); len(got) != 1 || got[0] != "eth0" {
		t.Fatalf("after reconcileActive, monitors = %v, want [eth0]", got)
	}

	// reconcileOnboarding stops monitoring (left ACTIVE).
	_ = s.reconcileOnboarding(ModeConverge)
	if got := s.netmon.Running(); len(got) != 0 {
		t.Fatalf("after reconcileOnboarding, monitors = %v, want none", got)
	}

	// Back to ACTIVE: a beginApply that FAILS (here: a scope with no pool plan)
	// must NOT tear down monitoring - the box stays ACTIVE and monitoring must
	// keep running. Teardown happens in finishApply, which runs only on a
	// committed apply.
	_ = s.reconcileActive(ModeConverge, 0)
	if len(s.netmon.Running()) == 0 {
		t.Fatal("expected monitors running before beginApply")
	}
	_ = s.sqlite.SetState(db.LifecycleStateKey, db.StateOnboarding) // beginApply needs a sane origin
	if _, err := s.beginApply("test2", []ScopeConfig{{Preset: "greengo", CIDR: "10.0.0.0/24"}}, UplinkConfig{}); err == nil {
		t.Fatal("expected beginApply to fail on a scope with no pool plan")
	}
	s.applying.Store(false) // release the guard the failed apply took
	if got := s.netmon.Running(); len(got) == 0 {
		t.Fatal("a FAILED beginApply must leave monitoring running (it stays ACTIVE)")
	}
}

// TestMulticastSniff_PersistRoundTrip covers the one place the feature reaches
// into core plumbing (migration 0006 + ScopeConfig.MulticastSniff + the INSERT):
// a scope persisted with multicast-sniff on loads back with it on.
func TestMulticastSniff_PersistRoundTrip(t *testing.T) {
	s, _ := newTestServer(t)
	plan := &applyPlan{}
	scopes := []ScopeConfig{
		{Preset: "greengo", CIDR: "10.0.0.0/24", MulticastSniff: true},
		{Preset: "dante", VlanID: 20, CIDR: "10.0.20.0/24", MulticastSniff: false},
	}
	if err := s.persistProfile("rt", scopes, plan); err != nil {
		t.Fatalf("persistProfile: %v", err)
	}
	loaded, err := s.loadScopeConfigs(plan.newProfileID)
	if err != nil {
		t.Fatalf("loadScopeConfigs: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d scopes, want 2", len(loaded))
	}
	got := map[string]bool{}
	for _, sc := range loaded {
		got[sc.CIDR] = sc.MulticastSniff
	}
	if !got["10.0.0.0/24"] {
		t.Error("multicast_sniff lost on round-trip for the greengo scope")
	}
	if got["10.0.20.0/24"] {
		t.Error("multicast_sniff wrongly set on the dante scope")
	}
}
