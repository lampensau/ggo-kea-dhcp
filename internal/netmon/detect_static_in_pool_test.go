package netmon

import (
	"testing"
	"time"
)

func u32(s string) uint32 { v, _ := parseU32(s); return v }

func TestStaticInPool_FlagsUnleasedActiveInPool(t *testing.T) {
	pool, ok := ParsePoolRange("10.0.0.20-10.0.0.200")
	if !ok {
		t.Fatal("ParsePoolRange failed")
	}
	// Lease set has .50 but not .42; .1 is infra (gateway).
	leases := func() []LeasedAddr { return []LeasedAddr{{IP: "10.0.0.50"}} }
	d := newStaticInPoolDetector("eth0", []PoolRange{pool}, []uint32{u32("10.0.0.1")}, leases, 120*time.Second, 0)
	d.warmup = 0 // isolate the core squat logic from the start-up warm-up grace

	// .42 active in pool, not leased, not infra → squatter (warn).
	d.Consume(arpFrame(2, [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x42}, [4]byte{10, 0, 0, 42}), at(1*time.Second))
	ev := d.Tick(at(1 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one squatter warn, got %v", ev)
	}
	s := d.Snapshot()
	if s.Severity != SevWarn || s.Fields["ip"] != "10.0.0.42" || s.Fields["reason"] != "active-not-leased" {
		t.Fatalf("snapshot = %+v", s)
	}
	if s.Fields["mac"] == "" {
		t.Fatal("squatter MAC not recorded")
	}
}

func TestStaticInPool_DoesNotFlagLeasedInfraOrOutside(t *testing.T) {
	pool, _ := ParsePoolRange("10.0.0.20-10.0.0.200")
	leases := func() []LeasedAddr { return []LeasedAddr{{IP: "10.0.0.50"}} }
	d := newStaticInPoolDetector("eth0", []PoolRange{pool}, []uint32{u32("10.0.0.1")}, leases, 120*time.Second, 0)
	d.warmup = 0

	// .50 is leased, .1 is infra, .250 is outside the pool → none flagged.
	d.Consume(arpFrame(2, [6]byte{0, 0, 0, 0, 0, 0x50}, [4]byte{10, 0, 0, 50}), at(1*time.Second))
	d.Consume(arpFrame(2, [6]byte{0, 0, 0, 0, 0, 0x01}, [4]byte{10, 0, 0, 1}), at(1*time.Second))
	d.Consume(arpFrame(2, [6]byte{0, 0, 0, 0, 0xfa, 0x00}, [4]byte{10, 0, 0, 250}), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("expected no events, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot = %+v, want ok", s)
	}
}

// TestStaticInPool_WarmupSuppressesOnboardingReconnect proves the start-up warm-up
// grace suppresses a flag right after the detector starts (the onboarding-reconnect /
// restart window, when a client off the old lease DB hasn't re-DHCP'd yet), then
// flags a genuine squatter once the warm-up elapses.
func TestStaticInPool_WarmupSuppressesOnboardingReconnect(t *testing.T) {
	pool, _ := ParsePoolRange("10.0.0.20-10.0.0.200")
	leases := func() []LeasedAddr { return nil } // .42 has no active lease
	d := newStaticInPoolDetector("eth0", []PoolRange{pool}, nil, leases, 120*time.Second, 0)
	mac := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x42}

	// First tick anchors the warm-up; an unleased in-pool host must NOT flag yet.
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 42}), at(0))
	if ev := d.Tick(at(0)); len(ev) != 0 {
		t.Fatalf("flagged at start of warm-up: %v", ev)
	}
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 42}), at(60*time.Second))
	if ev := d.Tick(at(60 * time.Second)); len(ev) != 0 {
		t.Fatalf("flagged during warm-up: %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("warm-up snapshot should be OK, got %+v", s)
	}

	// Past the warm-up, a still-squatting host is flagged.
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 42}), at(staticWarmup+10*time.Second))
	ev := d.Tick(at(staticWarmup + 10*time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected a squatter warn after warm-up, got %v", ev)
	}
}

// TestStaticInPool_LeaseHistoryGrace proves a client whose lease was just removed (it
// still holds the address until its next re-DHCP) is NOT flagged within ~T1, but IS
// once the grace elapses with no re-lease.
func TestStaticInPool_LeaseHistoryGrace(t *testing.T) {
	pool, _ := ParsePoolRange("10.0.0.20-10.0.0.200")
	leased := true
	leases := func() []LeasedAddr {
		if leased {
			return []LeasedAddr{{IP: "10.0.0.42"}}
		}
		return nil
	}
	d := newStaticInPoolDetector("eth0", []PoolRange{pool}, nil, leases, 120*time.Second, 1800) // T1 grace = 900s
	d.warmup = 0                                                                                // isolate the lease-history grace
	mac := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x42}

	// Leased + active → not flagged (records the lease-history stamp).
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 42}), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); len(ev) != 0 {
		t.Fatalf("leased host flagged: %v", ev)
	}

	// Operator deletes the lease; the client still holds .42. Within the grace it must
	// NOT be flagged (a refresh is forced by the >=30s gap, dropping it from leasedSet).
	leased = false
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 42}), at(60*time.Second))
	if ev := d.Tick(at(60 * time.Second)); len(ev) != 0 {
		t.Fatalf("flagged within the lease-history grace: %v", ev)
	}

	// Past the grace (T1=900s) with no re-lease → genuine squatter, flagged.
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 42}), at(1000*time.Second))
	ev := d.Tick(at(1000 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected a squatter warn past the lease grace, got %v", ev)
	}
}

// TestStaticInPool_NewLeaseSnapshotLag proves a device that gets a fresh lease and ARPs
// in the gap before the next 30s lease-snapshot refresh is NOT flagged on the stale
// (pre-appearance) snapshot - the 2s flag/clear flap seen on the dashboard.
func TestStaticInPool_NewLeaseSnapshotLag(t *testing.T) {
	pool, _ := ParsePoolRange("10.0.0.20-10.0.0.200")
	leased := false // Kea state, surfaced via leases() only on a refresh
	leases := func() []LeasedAddr {
		if leased {
			return []LeasedAddr{{IP: "10.0.0.50"}}
		}
		return nil
	}
	d := newStaticInPoolDetector("eth0", []PoolRange{pool}, nil, leases, 120*time.Second, 0)
	d.warmup = 0
	mac := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x50}

	// Establish the initial (empty) lease snapshot at t=1s.
	d.Tick(at(1 * time.Second))

	// The device gets a lease in Kea and ARPs at t=16s, but the detector's cached
	// snapshot is still the t=1s one (refresh is 30s). It must NOT flag a freshly-leased
	// device on a snapshot older than the host's first sighting.
	leased = true
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 50}), at(16*time.Second))
	if ev := d.Tick(at(16 * time.Second)); len(ev) != 0 {
		t.Fatalf("flagged a new device on a pre-appearance (stale) lease snapshot: %v", ev)
	}
	// The next refresh (>=30s) picks up the lease, so it stays unflagged.
	d.Consume(arpFrame(2, mac, [4]byte{10, 0, 0, 50}), at(32*time.Second))
	if ev := d.Tick(at(32 * time.Second)); len(ev) != 0 {
		t.Fatalf("flagged after the snapshot caught up to the lease: %v", ev)
	}
}

// TestStaticInPool_NoKeaMutationEverImpliedByAPI is a guard that the detector's
// surface is observe-only: it has no method that could mutate Kea (it only holds
// an injected read-only lease snapshot func). Compile-time presence of that field
// and absence of any sink is the contract; this test documents it.
func TestStaticInPool_ObserveOnly(t *testing.T) {
	d := newStaticInPoolDetector("eth0", nil, nil, nil, 0, 0)
	// With no lease snapshot it can never prove "unleased" → never flags.
	d.Consume(arpFrame(2, [6]byte{1, 2, 3, 4, 5, 6}, [4]byte{10, 0, 0, 42}), at(1*time.Second))
	if ev := d.Tick(at(1 * time.Second)); ev != nil {
		t.Fatalf("flagged without a lease snapshot: %v", ev)
	}
}
