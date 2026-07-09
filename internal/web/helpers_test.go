package web

import (
	"net"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

func TestIPToUint32RoundTrip(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "10.0.0.1", "192.168.1.254", "255.255.255.255"} {
		ip := net.ParseIP(s).To4()
		if got := kea.Uint32ToIP(kea.IPToUint32(ip)).String(); got != s {
			t.Errorf("round trip %s -> %s", s, got)
		}
	}
}

func TestRangeBounds(t *testing.T) {
	lo, hi, ok := kea.ParsePoolRange("10.0.0.1 - 10.0.0.10")
	wantLo := kea.IPToUint32(net.ParseIP("10.0.0.1").To4())
	wantHi := kea.IPToUint32(net.ParseIP("10.0.0.10").To4())
	if !ok || lo != wantLo || hi != wantHi {
		t.Errorf("rangeBounds good case: lo=%d hi=%d ok=%v want lo=%d hi=%d", lo, hi, ok, wantLo, wantHi)
	}
	if _, _, ok := kea.ParsePoolRange("10.0.0.1"); ok {
		t.Error("range missing separator should not parse")
	}
	if _, _, ok := kea.ParsePoolRange("bad - range"); ok {
		t.Error("non-ip bounds should not parse")
	}
}

func TestParseRangeCapacity(t *testing.T) {
	if got := parseRangeCapacity("10.0.0.1 - 10.0.0.10"); got != 10 {
		t.Errorf("capacity = %d want 10", got)
	}
	if got := parseRangeCapacity("10.0.0.1"); got != 0 {
		t.Errorf("malformed range capacity = %d want 0", got)
	}
	if got := parseRangeCapacity("bad - range"); got != 0 {
		t.Errorf("non-ip range capacity = %d want 0", got)
	}
	// Full-width range must report its real count, not wrap uint32 to 0.
	if got := parseRangeCapacity("0.0.0.0 - 255.255.255.255"); got != 1<<32 {
		t.Errorf("full-range capacity = %d want %d", got, int64(1)<<32)
	}
}

func TestRelativeAgo(t *testing.T) {
	const now = 1_000_000
	cases := []struct {
		then int64
		want string
	}{
		{0, ""},
		{now - 30, "just now"},
		{now - 300, "5m ago"},
		{now - 7200, "2h ago"},
		{now - 3*86400, "3d ago"},
	}
	for _, c := range cases {
		if got := relativeAgo(c.then, now); got != c.want {
			t.Errorf("relativeAgo(%d, %d) = %q, want %q", c.then, now, got, c.want)
		}
	}
}

func TestBuildLeaseRows(t *testing.T) {
	// No cltt/valid-lft (e.g. a reservation or absent timing); expiry renders as an
	// em dash. (The remaining-time formatting is covered deterministically by
	// TestLeaseExpiry; the cltt+valid-lft combination by TestLeaseExpiryFrom.)
	rows := buildLeaseRows([]kea.ActiveLease{
		{IPAddress: "10.0.0.50", HWAddress: "001f8020aaaa", ClientID: "cid", Hostname: "host"},
	})
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.IPAddress != "10.0.0.50" || r.Hostname != "host" || r.ExpiresIn != "—" {
		t.Errorf("row fields wrong: %+v", r)
	}
	if r.Class != "GGO-BPX" {
		t.Errorf("class = %q want GGO-BPX", r.Class)
	}
}
