package kea

import (
	"net"
	"testing"
)

// harness_kea_addr_test.go: verification tests for the IPv4 address-geometry
// helpers (addr.go / renderer.go IncIP) and LayoutPools edge cases. These are the
// "money path" arithmetic that every pool range is computed from.

// TestIPUint32RoundTrip proves IPToUint32 and Uint32ToIP are exact inverses
// across boundary values and a sweep, so the uint32 domain the allocator works in
// never silently corrupts an address.
func TestIPUint32RoundTrip(t *testing.T) {
	cases := []struct {
		ip string
		n  uint32
	}{
		{"0.0.0.0", 0},
		{"0.0.0.1", 1},
		{"10.0.0.0", 0x0A000000},
		{"10.0.0.1", 0x0A000001},
		{"192.168.1.254", 0xC0A801FE},
		{"255.255.255.255", 0xFFFFFFFF},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip).To4()
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := IPToUint32(ip); got != c.n {
			t.Errorf("IPToUint32(%s) = %#x, want %#x", c.ip, got, c.n)
		}
		if got := Uint32ToIP(c.n).String(); got != c.ip {
			t.Errorf("Uint32ToIP(%#x) = %s, want %s", c.n, got, c.ip)
		}
		// Full inverse both directions.
		if back := IPToUint32(Uint32ToIP(c.n)); back != c.n {
			t.Errorf("Uint32ToIP->IPToUint32(%#x) = %#x", c.n, back)
		}
	}
}

// TestIPToUint32NonV4 documents that IPToUint32 returns 0 for a non-IPv4
// input (the helper's defined fallback), rather than panicking.
func TestIPToUint32NonV4(t *testing.T) {
	if got := IPToUint32(net.ParseIP("::1")); got != 0 {
		t.Errorf("IPToUint32(::1) = %#x, want 0 (non-IPv4 fallback)", got)
	}
}

// TestIncIP exercises IncIP including a carry across octets, a zero
// increment, and the documented relationship IncIP(ip,n) == ip+n in uint32 space.
func TestIncIP(t *testing.T) {
	cases := []struct {
		base string
		off  int
		want string
	}{
		{"10.0.0.0", 1, "10.0.0.1"},
		{"10.0.0.0", 100, "10.0.0.100"},
		{"10.0.0.0", 250, "10.0.0.250"},
		{"10.0.0.0", 256, "10.0.1.0"},   // carry into the third octet
		{"10.0.0.255", 1, "10.0.1.0"},   // carry across one octet
		{"10.0.255.255", 1, "10.1.0.0"}, // carry across two octets
		{"10.0.0.5", 0, "10.0.0.5"},     // identity
	}
	for _, c := range cases {
		base := net.ParseIP(c.base).To4()
		got := IncIP(base, c.off).String()
		if got != c.want {
			t.Errorf("IncIP(%s, %d) = %s, want %s", c.base, c.off, got, c.want)
		}
		// Cross-check against the uint32 arithmetic the allocator relies on.
		if u := IPToUint32(base) + uint32(c.off); Uint32ToIP(u).String() != got {
			t.Errorf("IncIP(%s,%d) disagrees with uint32 add (%s vs %s)", c.base, c.off, got, Uint32ToIP(u))
		}
	}
}

// TestIncIPDoesNotMutate confirms IncIP returns a fresh slice and leaves the
// caller's net.IP untouched (it allocates + copies), so a shared subnet base used to
// derive several addresses is never clobbered.
func TestIncIPDoesNotMutate(t *testing.T) {
	base := net.ParseIP("10.0.0.0").To4()
	orig := base.String()
	_ = IncIP(base, 42)
	if base.String() != orig {
		t.Errorf("IncIP mutated its input: %s (was %s)", base.String(), orig)
	}
}

// TestParsePoolRangeRoundTrip checks ParsePoolRange against the exact
// "start - end" form the allocator emits, the space-less tolerant form, and a couple
// of malformed inputs (the ok=false contract).
func TestParsePoolRange(t *testing.T) {
	lo, hi, ok := ParsePoolRange("10.0.0.20 - 10.0.0.59")
	if !ok || lo != IPToUint32(net.ParseIP("10.0.0.20").To4()) || hi != IPToUint32(net.ParseIP("10.0.0.59").To4()) {
		t.Errorf("ParsePoolRange canonical form failed: lo=%#x hi=%#x ok=%v", lo, hi, ok)
	}
	// Tolerant of no surrounding spaces.
	if _, _, ok := ParsePoolRange("10.0.0.1-10.0.0.2"); !ok {
		t.Error("ParsePoolRange should tolerate the space-less 'a-b' form")
	}
	for _, bad := range []string{"", "garbage", "10.0.0.1", "not.an.ip - 10.0.0.2", "10.0.0.1 - notanip"} {
		if _, _, ok := ParsePoolRange(bad); ok {
			t.Errorf("ParsePoolRange(%q) = ok, want failure", bad)
		}
	}
}

// TestLayoutPoolsTinySubnets walks the small-subnet boundary of the
// allocator: a /30 (a single usable pool address at network+2), a /29, and the /31
// that has no room for any pool. A /30 has exactly one poolable address, so only a
// Fixed Size:1 fits - an elastic there hits the min-pool floor (covered separately).
func TestLayoutPoolsTinySubnets(t *testing.T) {
	// /30: usable hosts .1 and .2; gateway reserves network+1 (.1); pools begin at
	// network+2 (.2). So exactly one address is poolable - a Fixed Size:1 pool.
	got, err := LayoutPools("10.0.0.0/30", []PoolSpec{{Class: "A", Kind: PoolFixed, Size: 1}})
	if err != nil {
		t.Fatalf("LayoutPools /30 fixed: %v", err)
	}
	if len(got) != 1 || got[0].Range != "10.0.0.2 - 10.0.0.2" {
		t.Errorf("/30 single-address fixed pool = %+v, want [10.0.0.2 - 10.0.0.2]", got)
	}

	// /29: usable .1..6; pools .2..6 → a single elastic takes the whole 5-address span
	// (exactly the min-pool floor of 5).
	got, err = LayoutPools("10.0.0.0/29", []PoolSpec{{Class: "A", Kind: PoolElastic, Weight: 1}})
	if err != nil {
		t.Fatalf("LayoutPools /29 elastic: %v", err)
	}
	if got[0].Range != "10.0.0.2 - 10.0.0.6" {
		t.Errorf("/29 elastic pool = %q, want 10.0.0.2 - 10.0.0.6", got[0].Range)
	}

	// /31: broadcast < network+2, so subnetUsableBounds reports no usable host and
	// LayoutPools must reject it rather than emit an inverted range.
	if _, err := LayoutPools("10.0.0.0/31", []PoolSpec{{Class: "A", Kind: PoolElastic, Weight: 1}}); err == nil {
		t.Error("LayoutPools(/31) should error: no usable pool space")
	}
	// /32: single host, likewise unusable.
	if _, err := LayoutPools("10.0.0.0/32", []PoolSpec{{Class: "A", Kind: PoolElastic, Weight: 1}}); err == nil {
		t.Error("LayoutPools(/32) should error: no usable pool space")
	}
}

// TestLayoutPoolsElasticFloorOnTinySubnet proves a /30 (one poolable address)
// is rejected for an elastic pool that can't reach the min-pool floor (5) once a
// reserve eats the space - i.e. the floor guard fires rather than emitting a
// sub-floor pool.
func TestLayoutPoolsElasticFloorOnTinySubnet(t *testing.T) {
	// /28 = 16 addrs, poolable .2..14 = 13. A reserve of 10 leaves 3 free, below the
	// elastic min-pool floor of 5 → error.
	_, err := LayoutPools("10.0.0.0/28", []PoolSpec{
		{Kind: PoolReserve, Size: 10},
		{Class: "FILL", Kind: PoolElastic, Weight: 1},
	})
	if err == nil {
		t.Error("expected an elastic-below-floor error when a reserve starves the pool")
	}
}

// TestLayoutPoolsPinnedRangesNoOverlap is a stronger pinned-overlap check than
// the existing suite: two adjacent pins that touch but do NOT overlap must both be
// honored verbatim, and the trailing elastic fills the remaining gap.
func TestLayoutPoolsAdjacentPinsHonored(t *testing.T) {
	got, err := LayoutPools("10.0.0.0/24", []PoolSpec{
		{Class: "A", Kind: PoolFixed, Range: "10.0.0.10 - 10.0.0.19"},
		{Class: "B", Kind: PoolFixed, Range: "10.0.0.20 - 10.0.0.29"}, // touches A at the boundary, no overlap
		{Class: "FILL", Kind: PoolElastic, Weight: 1},
	})
	if err != nil {
		t.Fatalf("adjacent (non-overlapping) pins should be accepted: %v", err)
	}
	if got[0].Range != "10.0.0.10 - 10.0.0.19" || got[1].Range != "10.0.0.20 - 10.0.0.29" {
		t.Errorf("pinned ranges not honored verbatim: %+v", got)
	}
	// FILL packs the low gap (.2..9) first-fit before the trailing space; assert it is
	// a valid in-bounds range, not the whole subnet.
	lo, hi, ok := ParsePoolRange(got[2].Range)
	if !ok || lo > hi {
		t.Errorf("elastic FILL range invalid: %q", got[2].Range)
	}
}

// TestLayoutPoolsNegativeSizeRejected locks the negative-size guard.
func TestLayoutPoolsNegativeSizeRejected(t *testing.T) {
	if _, err := LayoutPools("10.0.0.0/24", []PoolSpec{{Class: "A", Kind: PoolFixed, Size: -1}}); err == nil {
		t.Error("expected an error for a negative Fixed size")
	}
}
