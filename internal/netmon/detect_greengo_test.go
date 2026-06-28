package netmon

import (
	"strings"
	"testing"
	"time"
)

// hFrame builds a minimal UDP-5810 'h' broadcast from srcMAC/srcIP, optionally
// 802.1Q-tagged with vid (0 = untagged). The greengo presence path needs only the
// headers (source MAC + IP + tag), not the G5 payload, so this omits it.
func hFrame(srcMAC [6]byte, srcIP [4]byte, vid int) []byte {
	off := 14
	if vid != 0 {
		off = 18
	}
	b := make([]byte, off+20+8)
	for i := range 6 {
		b[i] = 0xff // dst broadcast
	}
	copy(b[6:12], srcMAC[:])
	if vid != 0 {
		b[12], b[13] = 0x81, 0x00 // 802.1Q
		b[14] = byte(vid >> 8)
		b[15] = byte(vid)
		b[16], b[17] = 0x08, 0x00 // inner IPv4
	} else {
		b[12], b[13] = 0x08, 0x00 // IPv4
	}
	b[off] = 0x45 // IPv4 version 4, IHL 5
	b[off+9] = 17 // proto UDP
	copy(b[off+12:off+16], srcIP[:])
	l4 := off + 20
	b[l4], b[l4+1] = 0x16, 0xb2   // sport 5810
	b[l4+2], b[l4+3] = 0x16, 0xb2 // dport 5810
	return b
}

// TestGreengoForeignVLAN: an Evenution device heard only via its 'h' broadcast, on a
// VLAN we do not serve, is reported as "on unserved VLAN N" - never folded into the
// served census - and is found via 'h' alone (no ARP), so it survives a restart.
func TestGreengoForeignVLAN(t *testing.T) {
	d := newGreengoDetector("eth0", func() []LeasedAddr { return nil }, 0, 0) // serve untagged VID 0
	bpx := [6]byte{0x00, 0x1f, 0x80, 0x20, 0x4e, 0x52}
	feed := func(now time.Time) {
		d.Consume(Frame{Data: hFrame(bpx, [4]byte{169, 254, 78, 82}, 200)}, now) // 'h' on VLAN 200
	}
	start := time.Unix(1000, 0)
	feed(start)
	d.Tick(start)
	now := start.Add(time.Second)
	feed(now)
	d.Tick(now)

	s := d.Snapshot()
	if s.Severity != SevWarn || !strings.Contains(s.Text, "unserved") || !strings.Contains(s.Text, "200") {
		t.Fatalf("foreign-VLAN 'h' device should warn 'unserved ... 200', got %+v", s)
	}
	if s.Fields["foreign"] != "1" {
		t.Errorf("foreign = %q, want 1", s.Fields["foreign"])
	}
	if s.Fields["devices"] != "" {
		t.Errorf("served census should be empty (the device is on a foreign VLAN), got devices=%q", s.Fields["devices"])
	}
}

// arpFrameFor builds a minimal broadcast ARP request with the given sender MAC/IP,
// laid out exactly as Consume parses it (ethertype at 12, ARP at 14, sha at +8,
// spa at +14).
func arpFrameFor(srcMAC [6]byte, srcIP [4]byte) []byte {
	b := make([]byte, 42)
	for i := range 6 {
		b[i] = 0xff // dst broadcast
	}
	copy(b[6:12], srcMAC[:])
	b[12], b[13] = 0x08, 0x06 // EtherType ARP
	b[14], b[15] = 0x00, 0x01 // htype ethernet
	b[16], b[17] = 0x08, 0x00 // ptype IPv4
	b[18], b[19] = 6, 4       // hlen, plen
	b[20], b[21] = 0x00, 0x01 // op request
	copy(b[22:28], srcMAC[:]) // sha
	copy(b[28:32], srcIP[:])  // spa
	return b
}

func TestGgoFamily(t *testing.T) {
	cases := []struct {
		mac  [6]byte
		want string
	}{
		{[6]byte{0x00, 0x1f, 0x80, 0x20, 0x4e, 0x5e}, "BPX"},            // BPX block 0x204000
		{[6]byte{0x00, 0x1f, 0x80, 0x22, 0x02, 0xf0}, "MCX(D)/EXT"},     // MCX block 0x220000
		{[6]byte{0x00, 0x1f, 0x80, 0x23, 0x03, 0x85}, "Stride Antenna"}, // 0x230000
		{[6]byte{0x00, 0x1f, 0x80, 0x99, 0x00, 0x00}, ""},               // outside any known block
	}
	for _, c := range cases {
		if got := ggoFamily(c.mac); got != c.want {
			t.Errorf("ggoFamily(%v) = %q, want %q", c.mac, got, c.want)
		}
	}
}

// During warm-up, a device whose IP is in the lease set is positively served, so the
// row should be green at once rather than waiting out the 3-minute warm-up.
func TestGreengoWarmupConfirmedServedIsOK(t *testing.T) {
	leased := []LeasedAddr{{IP: "10.0.0.50"}}
	d := newGreengoDetector("eth0", func() []LeasedAddr { return leased }, 0, 0)
	bpx := [6]byte{0x00, 0x1f, 0x80, 0x20, 0x4e, 0x5e} // BPX, leased
	start := time.Unix(1000, 0)
	d.Consume(Frame{Data: arpFrameFor(bpx, [4]byte{10, 0, 0, 50})}, start)
	d.Tick(start) // still inside warm-up
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("warm-up snapshot severity = %q, want ok (device is lease-confirmed)", s.Severity)
	}
}

func TestGreengoDetector(t *testing.T) {
	leased := []LeasedAddr{{IP: "10.0.0.50"}}
	d := newGreengoDetector("eth0", func() []LeasedAddr { return leased }, 0, 0)

	bpx := [6]byte{0x00, 0x1f, 0x80, 0x20, 0x4e, 0x5e}   // Beltpack X, will be leased
	mcx := [6]byte{0x00, 0x1f, 0x80, 0x22, 0x02, 0xf0}   // MCX, link-local (DHCP failed)
	other := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55} // non-Evenution, must be ignored

	start := time.Unix(1000, 0)
	feed := func(now time.Time) {
		d.Consume(Frame{Data: arpFrameFor(bpx, [4]byte{10, 0, 0, 50})}, now)
		d.Consume(Frame{Data: arpFrameFor(mcx, [4]byte{169, 254, 5, 9})}, now)
		d.Consume(Frame{Data: arpFrameFor(other, [4]byte{10, 0, 0, 60})}, now)
	}

	// First tick is inside the warm-up window: nothing should be flagged yet.
	feed(start)
	if ev := d.Tick(start); len(ev) != 0 {
		t.Fatalf("warm-up tick emitted events: %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevInfo {
		t.Fatalf("warm-up snapshot severity = %q, want info", s.Severity)
	}

	// Past warm-up: the link-local MCX must flag (one event), the non-Evenution device
	// must be ignored entirely.
	now := start.Add(staticWarmup + time.Second)
	feed(now)
	ev := d.Tick(now)
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("post-warmup events = %v, want one SevWarn (link-local)", ev)
	}

	s := d.Snapshot()
	if s.Kind != "greengo" || s.Severity != SevWarn {
		t.Fatalf("snapshot = %+v, want kind greengo severity warn", s)
	}
	if s.Fields["devices"] != "2" {
		t.Errorf("devices = %q, want 2 (BPX + MCX, not the non-Evenution host)", s.Fields["devices"])
	}
	if s.Fields["link_local"] != "1" {
		t.Errorf("link_local = %q, want 1", s.Fields["link_local"])
	}
	if s.Fields["no_lease"] != "" {
		t.Errorf("no_lease = %q, want empty (BPX is leased, MCX is link-local)", s.Fields["no_lease"])
	}
}

func TestGreengoNoLease(t *testing.T) {
	// A Green-GO device on a routable IP with no lease (static / wrong subnet) is a
	// card-severity warn, no audit event.
	d := newGreengoDetector("eth0", func() []LeasedAddr { return nil }, 0, 0)
	mcx := [6]byte{0x00, 0x1f, 0x80, 0x22, 0x02, 0xf0}
	start := time.Unix(1000, 0)
	d.Consume(Frame{Data: arpFrameFor(mcx, [4]byte{10, 0, 0, 70})}, start)
	d.Tick(start) // warm-up

	now := start.Add(staticWarmup + time.Second)
	d.Consume(Frame{Data: arpFrameFor(mcx, [4]byte{10, 0, 0, 70})}, now)
	if ev := d.Tick(now); len(ev) != 0 {
		t.Fatalf("no-lease must not audit, got %v", ev)
	}
	s := d.Snapshot()
	if s.Severity != SevWarn || s.Fields["no_lease"] != "1" {
		t.Fatalf("snapshot = %+v, want SevWarn no_lease=1", s)
	}
}
