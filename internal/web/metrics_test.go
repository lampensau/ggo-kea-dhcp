package web

import "testing"

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
