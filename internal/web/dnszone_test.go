package web

import (
	"net"
	"reflect"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/ggoscan"
	"ggo-kea-dhcp/internal/kea"
)

// net4 builds an IPv4 for the reservation fixtures.
func net4(a, b, c, d byte) net.IP { return net.IPv4(a, b, c, d).To4() }

// zoneLease builds a currently-valid lease for the zone-builder tests.
func zoneLease(ip, mac, hostname string) kea.ActiveLease {
	return kea.ActiveLease{IPAddress: ip, HWAddress: mac, Hostname: hostname, Cltt: time.Now().Unix(), ValidLft: 3600}
}

func TestBuildDNSHostsPrecedence(t *testing.T) {
	devs := []ggoscan.Device{
		{MAC: "00:1f:80:aa:00:01", Name: "BPX Stage", IP: "10.0.0.30"}, // scan only: online-but-unleased
		{MAC: "00:1f:80:aa:00:02", Name: "MCX FOH", IP: "10.0.0.31"},   // scan name, lease address wins
	}
	leases := []kea.ActiveLease{
		zoneLease("10.0.0.40", "00:1f:80:aa:00:02", ""),          // Green-GO: no DHCP hostname
		zoneLease("10.0.0.41", "aa:bb:cc:00:00:03", "Laptop 07"), // client-announced hostname
		zoneLease("10.0.0.42", "aa:bb:cc:00:00:04", "renamed"),   // reservation hostname must beat it
	}
	reservations := map[string]db.HostReservation{
		"aabbcc000004": {Hostname: "console-a", IPv4Address: kea.IPToUint32(net4(10, 0, 0, 42))},
		"aabbcc000005": {Hostname: "spare-desk", IPv4Address: kea.IPToUint32(net4(10, 0, 0, 200))}, // no lease: reserved address fills in
	}

	got := buildDNSHosts(devs, leases, reservations)
	want := map[string]string{
		"bpx-stage":  "10.0.0.30", // scan-only device published
		"mcx-foh":    "10.0.0.40", // lease address beats the scan-observed one
		"laptop-07":  "10.0.0.41",
		"console-a":  "10.0.0.42", // operator name beats the client's
		"spare-desk": "10.0.0.200",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildDNSHosts = %v, want %v", got, want)
	}
}

func TestBuildDNSHostsSkipsUnusableRows(t *testing.T) {
	devs := []ggoscan.Device{
		{MAC: "", Name: "no-identity", IP: "10.0.0.60"},          // MAC-less: never enters the funnel
		{MAC: "00:1f:80:aa:00:07", Name: "###", IP: "10.0.0.61"}, // sanitizes to an empty slug: skipped
		{MAC: "00:1f:80:aa:00:08", Name: "named-no-ip"},          // no address anywhere: skipped
	}
	got := buildDNSHosts(devs, nil, nil)
	if len(got) != 0 {
		t.Fatalf("unusable rows produced zone entries: %v", got)
	}
}

func TestBuildDNSHostsDeterministic(t *testing.T) {
	// A trunked device holding two leases (one per VLAN) and two scan rows must
	// publish the same address on every build - map iteration must not leak in.
	devs := []ggoscan.Device{
		{MAC: "00:1f:80:aa:00:09", Name: "trunked", IP: "10.30.0.9"},
	}
	leases := []kea.ActiveLease{
		zoneLease("10.30.0.9", "00:1f:80:aa:00:09", ""),
		zoneLease("10.20.0.9", "00:1f:80:aa:00:09", ""),
	}
	first := buildDNSHosts(devs, leases, nil)
	for i := 0; i < 20; i++ {
		if got := buildDNSHosts(devs, leases, nil); !reflect.DeepEqual(got, first) {
			t.Fatalf("build %d differs: %v vs %v", i, got, first)
		}
	}
	if first["trunked"] != "10.30.0.9" {
		t.Fatalf("trunked device published %s, want the highest-sorted lease address", first["trunked"])
	}
}

func TestGgoNamesSignatureOrderIndependent(t *testing.T) {
	a := map[string]string{"m1": "a", "m2": "b"}
	b := map[string]string{"m2": "b", "m1": "a"}
	if ggoNamesSignature(a) != ggoNamesSignature(b) {
		t.Fatal("signature depends on map order")
	}
	if ggoNamesSignature(a) == ggoNamesSignature(map[string]string{"m1": "a", "m2": "c"}) {
		t.Fatal("signature missed a name change")
	}
}
