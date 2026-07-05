package dns

import (
	"net"
	"testing"
)

// TestRebindMissingHealsAfterAddressAppears proves the DNS self-heal: an address
// whose bind failed at StartZone time (here simulated by holding the port, standing
// in for the address-not-yet-present post-re-IP race) is rebound by RebindMissing
// once the obstacle clears - without a fresh StartZone. This is the gap that
// otherwise left a scope's local DNS dark until the next full reconcile.
func TestRebindMissingHealsAfterAddressAppears(t *testing.T) {
	// An ephemeral loopback port, held open so the first bind fails.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("probe bind: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port

	srv := New("")
	srv.port = port // bind the unprivileged probe port, not :53

	failed := srv.StartZone([]string{"127.0.0.1"})
	if len(failed) != 1 || failed[0] != "127.0.0.1" {
		probe.Close()
		t.Fatalf("initial bind should fail while the port is held, got failed=%v", failed)
	}

	// Still held: nothing can heal yet.
	if healed := srv.RebindMissing(); len(healed) != 0 {
		probe.Close()
		t.Fatalf("RebindMissing healed while the port was still held: %v", healed)
	}

	// Free the port; the address can now bind.
	probe.Close()
	healed := srv.RebindMissing()
	if len(healed) != 1 || healed[0] != "127.0.0.1" {
		t.Fatalf("RebindMissing did not heal after the port freed: %v", healed)
	}

	// Idempotent: an already-bound address is not rebound.
	if again := srv.RebindMissing(); len(again) != 0 {
		t.Fatalf("RebindMissing re-bound an already-bound address: %v", again)
	}

	// After Stop the server is deliberately torn down: the heal must not resurrect it.
	srv.Stop()
	if healed := srv.RebindMissing(); healed != nil {
		t.Fatalf("RebindMissing resurrected a stopped server: %v", healed)
	}
}

// TestBindSetSnapshotIsACopy guards the forward-path concurrency fix: the forward
// path reads the snapshot unlocked while RebindMissing mutates the live bind set in
// place under the lock. If the snapshot shared that map, the two would be a
// concurrent map read+write (a fatal runtime throw). This proves the snapshot is an
// independent copy: an in-place rebind after the snapshot is taken must not leak
// into it.
func TestBindSetSnapshotIsACopy(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("probe bind: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port

	srv := New("")
	srv.port = port
	srv.StartZone([]string{"127.0.0.1"}) // port held: bind fails, bindSet stays empty
	snap := srv.bindSetSnapshot()

	probe.Close()
	if healed := srv.RebindMissing(); len(healed) != 1 { // mutates the live bindSet in place
		t.Fatalf("expected the freed address to heal, got %v", healed)
	}
	if snap["127.0.0.1"] {
		t.Fatal("snapshot is not a copy: a later in-place RebindMissing leaked into it")
	}
	srv.Stop()
}
