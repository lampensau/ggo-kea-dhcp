package dns

import (
	"reflect"
	"testing"
)

// FuzzParseQuestion exercises the DNS question decoder, which walks
// length-prefixed labels and compression pointers from untrusted UDP bytes -
// the classic overrun/loop shape (a pointer can aim anywhere, including at
// itself). Invariants: never panic, deterministic across a double parse, and a
// successful parse yields a question section that actually fits the packet.
func FuzzParseQuestion(f *testing.F) {
	f.Add(buildQuery(0x1234, "bpx-19."+SuffixInv, typeA))
	f.Add(buildQuery(1, "", typeA)) // root name
	// Pointer pointing at itself: the loop guard must trip.
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1})
	// Pointer into the header, then truncated.
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x00})
	f.Add([]byte{0, 1})     // shorter than a header
	f.Add([]byte(nil))      // empty
	f.Add(make([]byte, 12)) // header only, QDCOUNT 0

	f.Fuzz(func(t *testing.T, msg []byte) {
		q1, ok1 := parseQuestion(msg)
		q2, ok2 := parseQuestion(msg)
		if ok1 != ok2 || !reflect.DeepEqual(q1, q2) {
			t.Fatalf("parseQuestion not deterministic on %x", msg)
		}
		if ok1 {
			if q1.end < headerLen || q1.end > len(msg) {
				t.Fatalf("question end %d outside packet of %d bytes", q1.end, len(msg))
			}
			if len(q1.Name) > 255 {
				t.Fatalf("decoded name longer than the 255-octet limit: %d", len(q1.Name))
			}
		}
	})
}
