package netmon

import (
	"reflect"
	"testing"
)

// FuzzParseNibbleTLV exercises the Green-GO 'h'-heartbeat nibble-TLV decoder, which
// walks variable-length type/length headers from untrusted multicast bytes. The
// length accumulators (length<<8 | ...) and the pos+length bound are the panic risk.
// Invariants: never panic, and decoding is deterministic - the doc warns the input
// may alias the reusable frame buffer, so a second parse of the same bytes must yield
// an identical result (no aliasing/global-state leak between calls).
func FuzzParseNibbleTLV(f *testing.F) {
	f.Add([]byte{0x00})                   // immediate END
	f.Add([]byte{0x10, 0x00})             // type reset then END
	f.Add([]byte{0x21, 0xff})             // tdelta=1 length=2 but truncated
	f.Add([]byte{0xbf, 0xff, 0xff, 0xff}) // extended tdelta/length, truncated
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, buf []byte) {
		recs, ok := parseNibbleTLV(buf)
		recs2, ok2 := parseNibbleTLV(buf)
		if ok != ok2 || !reflect.DeepEqual(recs, recs2) {
			t.Fatalf("parseNibbleTLV not deterministic on %x", buf)
		}
	})
}

// FuzzParseDHCPOptions exercises the DHCP option walker used by the rogue-DHCP
// detector on untrusted server replies. Length-prefixed option walking is the classic
// buffer-overrun shape; the i+2+length bound must hold for every input. Invariants:
// never panic, and the parse is deterministic across repeated calls.
func FuzzParseDHCPOptions(f *testing.F) {
	f.Add([]byte{53, 1, 2, 255})      // DHCP Offer, then END
	f.Add([]byte{54, 4, 10, 0, 0, 1}) // server-id, no END
	f.Add([]byte{50, 4})              // option claims 4 bytes that aren't there
	f.Add([]byte{0, 0, 0})            // all pad
	f.Add([]byte{255})                // immediate END
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, opts []byte) {
		//lint:ignore SA4000 determinism check: parser is called twice on purpose
		if parseDHCPOptions(opts) != parseDHCPOptions(opts) {
			t.Fatalf("parseDHCPOptions not deterministic on %x", opts)
		}
	})
}

// FuzzParseAuxVLAN exercises the PACKET_AUXDATA control-message parser that recovers a
// hardware-stripped 802.1Q tag. It reads a cmsghdr out of raw oob bytes - a short or
// malformed control buffer must not panic. Invariant: a recovered VID is a real 12-bit
// 802.1Q id (0..4095); anything else means the &0x0fff mask regressed.
func FuzzParseAuxVLAN(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 4))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, oob []byte) {
		vid, known := parseAuxVLAN(oob)
		if known && (vid < 0 || vid > 4095) {
			t.Fatalf("parseAuxVLAN returned out-of-range VID %d on %x", vid, oob)
		}
	})
}
