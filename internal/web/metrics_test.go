package web

import (
	"fmt"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

func TestRingInt_WrapAndOrder(t *testing.T) {
	r := newRingInt(3)
	if got := r.series(); len(got) != 0 {
		t.Fatalf("empty ring series = %v, want []", got)
	}
	r.push(1)
	r.push(2)
	if got := r.series(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("series = %v, want [1 2]", got)
	}
	r.push(3)
	r.push(4) // overwrites the oldest (1)
	if got := r.series(); len(got) != 3 || got[0] != 2 || got[1] != 3 || got[2] != 4 {
		t.Fatalf("after wrap series = %v, want [2 3 4]", got)
	}
}

func TestMetricsStore_SignatureChangesPerSample(t *testing.T) {
	m := newMetricsStore()
	s0 := m.signature()
	m.push(1, 50, 5, -1, 1)
	s1 := m.signature()
	if s1 == s0 {
		t.Fatal("signature unchanged after a push")
	}
	if m.signature() != s1 {
		t.Fatal("signature changed without a push (ticker would re-render needlessly)")
	}
	m.push(1, 50, 5, -1, 1) // identical values still mean a new sample (sparkline window shifts)
	if m.signature() == s1 {
		t.Fatal("signature unchanged after a second push of identical values")
	}
}

func TestMetricsStore_Snapshot(t *testing.T) {
	m := newMetricsStore()
	m.push(10, 80, 7, -1, 0)
	m.push(12, 82, 9, 3, 1)
	snap := m.snapshot()
	if len(snap.LeaseCount) != 2 || snap.LeaseCount[0] != 10 || snap.LeaseCount[1] != 12 {
		t.Fatalf("LeaseCount = %v, want [10 12]", snap.LeaseCount)
	}
	if snap.PoolPct[1] != 82 || snap.KeaRTT[1] != 9 {
		t.Fatalf("snap = %+v", snap)
	}
	if snap.Uplink[0] != -1 || snap.Uplink[1] != 3 { // -1 sentinel = offline/no-probe
		t.Fatalf("Uplink = %v, want [-1 3]", snap.Uplink)
	}
	if snap.Ptp[0] != 0 || snap.Ptp[1] != 1 { // PTP grandmaster presence (0 absent, 1 locked)
		t.Fatalf("Ptp = %v, want [0 1]", snap.Ptp)
	}
}

// seedSamplerTrunk builds the sampler fixture shared by the allocation test and
// benchmark: an active profile with 5 scopes - 3 greengo (class-counted pools)
// and 2 range-counted (dante/sacn elastic pool), so both occupancy branches run -
// plus 300 leases spread across them.
func seedSamplerTrunk(tb testing.TB, s *Server) []kea.ActiveLease {
	tb.Helper()
	res, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('SamplerTest', 1)")
	if err != nil {
		tb.Fatalf("insert profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	for i, preset := range []string{"greengo", "dante", "greengo", "sacn", "greengo"} {
		cidr := fmt.Sprintf("10.0.%d.0/24", i)
		if _, err := s.sqlite.Exec(
			`INSERT INTO scopes (profile_id, vlan_id, cidr, preset, pool_spec, uplink_json)
			 VALUES (?, ?, ?, ?, '{}', '{}')`, pid, i*10, cidr, preset); err != nil {
			tb.Fatalf("insert scope %d: %v", i, err)
		}
	}
	leases := make([]kea.ActiveLease, 0, 300)
	for i := 0; i < 300; i++ {
		leases = append(leases, kea.ActiveLease{
			IPAddress: fmt.Sprintf("10.0.%d.%d", i%5, 20+i/5),
			HWAddress: fmt.Sprintf("00:1f:80:%02x:00:%02x", i%4*16, i),
		})
	}
	return leases
}

// TestSamplePoolUtilAllocCount pins the per-sample allocation cost of the always-on
// 12s sampler on a realistic trunk (5 scopes x 300 leases). Each lease's IP and class
// must be digested once per build (parseLeases), not once per scope per lease: the
// per-scope subnet filter used to net.ParseIP every lease against every scope and copy
// whole ActiveLease structs into its filtered slice, which roughly doubles allocations.
// The gate counts allocations, not bytes: allocation count is deterministic and
// architecture-independent (measured 961/run on both amd64 and arm64), where byte
// totals drift with Go releases and GC tuning. A reintroduced per-scope re-parse is
// ~1989/run, so the 1400 budget sits between the two regimes and fails the regression
// while normal churn does not.
//
// AllocsPerRun counts allocations on the calling goroutine only, so this gate assumes
// samplePoolUtil stays synchronous (it is: sqlite query -> parseLeases -> per-scope
// poolDataForScope, all inline). If it ever offloads work to background workers, their
// allocations would not be counted and the gate would silently go blind to them.
func TestSamplePoolUtilAllocCount(t *testing.T) {
	s, _ := newTestServer(t)
	leases := seedSamplerTrunk(t, s)
	s.samplePoolUtil(leases) // warm caches (sqlite prepared statements etc.)

	allocs := testing.AllocsPerRun(50, func() { s.samplePoolUtil(leases) })
	const budget = 1400
	if allocs > budget {
		t.Fatalf("samplePoolUtil made %.0f allocs/run for 5 scopes x 300 leases, budget %d (leases must be parsed once per build, not per scope)", allocs, budget)
	}
}

// BenchmarkSamplePoolUtil measures one always-on sampler pool-utilization pass
// (5 scopes x 300 leases), the every-12s viewer-independent cost on the Pi.
func BenchmarkSamplePoolUtil(b *testing.B) {
	s, _ := newTestServer(b)
	leases := seedSamplerTrunk(b, s)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.samplePoolUtil(leases)
	}
}
