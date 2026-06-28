package netmon

import (
	"testing"
	"time"
)

// g5Encrypt is the inverse of g5DecryptPayload, used only to synthesize test 'h'
// frames. The key schedule is driven by the plaintext word sum (acc), identical on
// both sides, so encryption is the same transform with ct = ror(K)^p. checksum is
// chosen so the decoder's (checksum+acc)==0 gate passes. plain must be 16-aligned.
func g5Encrypt(plain []byte, seed uint32) (cipher []byte, checksum uint32) {
	nblocks := len(plain) / 16
	out := make([]byte, nblocks*16)
	copy(out, plain)
	k := seed
	var acc uint32
	for i := range nblocks {
		o := i * 16
		p0, p1, p2, p3 := leu32(out, o), leu32(out, o+4), leu32(out, o+8), leu32(out, o+12)
		putLEu32(out, o, ror32(k, 6)^p0)
		putLEu32(out, o+4, ror32(k, 19)^p1)
		putLEu32(out, o+8, ror32(k, 1)^p2)
		putLEu32(out, o+12, ror32(k, 7)^p3)
		acc += p0 + p1 + p2 + p3
		k = ror32(k, 15) + acc
	}
	return out, -acc
}

// hVector is a reference 'h' TLV plaintext: t1 configId 06da8e3d14e247a0, t2
// multicast 239.1.95.231 (ef015fe7), t4 name "abba".
var hVector = []byte{
	0x81, 0x06, 0xda, 0x8e, 0x3d, 0x14, 0xe2, 0x47, 0xa0, // t1 configId (8B)
	0x41, 0xef, 0x01, 0x5f, 0xe7, // t2 multicast group (4B)
	0x42, 0x61, 0x62, 0x62, 0x61, // t4 "abba"
}

// g5HFrame wraps a TLV plaintext into a full encrypted 'h' (0x68) frame inside
// UDP:5810 → IPv4 → Ethernet.
func g5HFrame(seed uint32, tlv []byte) []byte {
	plen := (len(tlv) + 15) &^ 15
	plain := make([]byte, plen)
	copy(plain, tlv)
	cipher, cksum := g5Encrypt(plain, seed)
	g5 := make([]byte, 14+len(cipher))
	g5[0], g5[1], g5[2], g5[3] = 0x47, 0x35, 0x68, 0x81 // "G5", subtype 'h', flags encrypted
	putLEu32(g5, 6, seed)
	putLEu32(g5, 10, cksum)
	copy(g5[14:], cipher)
	udp := buildUDP(ggoBusPort, ggoBusPort, g5)
	ip := buildIPv4(ipProtoUDP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 255}, udp)
	return buildEth(macTestSwitch, macTestSwitch, etherTypeIPv4, ip)
}

func TestG5DecryptAndTLV(t *testing.T) {
	plain := make([]byte, 32)
	copy(plain, hVector)
	cipher, cksum := g5Encrypt(plain, 0x12345678)
	dec, ok := g5DecryptPayload(cipher, 0x12345678, cksum)
	if !ok {
		t.Fatal("checksum validation failed on round-tripped frame")
	}
	recs, ok := parseNibbleTLV(dec)
	if !ok {
		t.Fatal("nibble-TLV parse failed")
	}
	var id, group, name string
	for _, r := range recs {
		switch r.typ {
		case 1:
			if len(r.value) == 8 {
				id = hex64(be64(r.value, 0))
			}
		case 2:
			if len(r.value) == 4 {
				group = ipString([4]byte{r.value[0], r.value[1], r.value[2], r.value[3]})
			}
		case 4:
			name = asciiTrim(r.value)
		}
	}
	if id != "06da8e3d14e247a0" {
		t.Errorf("configId = %q, want 06da8e3d14e247a0", id)
	}
	if group != "239.1.95.231" {
		t.Errorf("group = %q, want 239.1.95.231", group)
	}
	if name != "abba" {
		t.Errorf("name = %q, want abba", name)
	}
}

func TestGreengoHDetector(t *testing.T) {
	d := newGreengoHDetector("eth0", 0, 0)
	now := time.Unix(1000, 0)

	d.Consume(Frame{Data: g5HFrame(0x12345678, hVector)}, now)
	if ev := d.Tick(now); len(ev) != 0 {
		t.Fatalf("single config emitted events: %v", ev)
	}
	s := d.Snapshot()
	// Exactly one config on the segment is the expected healthy (OK) state.
	if s.Kind != "greengo_config" || s.Severity != SevOK {
		t.Fatalf("snapshot = %+v, want greengo_config/ok", s)
	}
	if s.Fields["config"] != "abba" || s.Fields["group"] != "239.1.95.231" {
		t.Errorf("fields = %v, want config=abba group=239.1.95.231", s.Fields)
	}

	// A second, distinct config on the same segment must raise the multiple-configs
	// warning with one audit event.
	tlv2 := []byte{
		0x81, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // t1 different configId
		0x41, 0xef, 0x01, 0x6e, 0x69, // t2 group 239.1.110.105
		0x42, 0x62, 0x62, 0x62, 0x62, // t4 "bbbb"
	}
	d.Consume(Frame{Data: g5HFrame(0xabcdef01, tlv2)}, now)
	ev := d.Tick(now)
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("two configs: events = %v, want one SevWarn", ev)
	}
	s = d.Snapshot()
	if s.Severity != SevWarn || s.Fields["configs"] != "2" {
		t.Fatalf("snapshot = %+v, want SevWarn configs=2", s)
	}

	// After the second config ages out, it returns to the single-config healthy (OK)
	// state with a clear event.
	later := now.Add(greengoConfigAbsence + time.Second)
	d.Consume(Frame{Data: g5HFrame(0x12345678, hVector)}, later) // only the first re-announces
	ev = d.Tick(later)
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("aged-out: events = %v, want one SevInfo (cleared)", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("after age-out severity = %q, want ok", s.Severity)
	}
}
