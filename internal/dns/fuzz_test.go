package dns

import (
	"bytes"
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

// FuzzHandle fuzzes listener.handle end to end - the query dispatch beyond the
// question parser: respond's echo/answer slicing, reverseName, and the apex/zone
// branches, plus the response contract. handle touches only bindIP and the atomic
// zone pointer (it never does the network I/O - the caller forwards), so a plain
// listener over a fixed zone exercises it. Property: never panic; a non-nil
// response is at most 512 bytes and echoes the request's txid.
func FuzzHandle(f *testing.F) {
	srv := New("")
	srv.SetZone(testZone())
	l := &listener{srv: srv, bindIP: [4]byte{10, 0, 0, 1}}

	f.Add(buildQuery(0x1234, "bpx-19."+SuffixInv, typeA))
	f.Add(buildQuery(0x2222, "99.0.0.10.in-addr.arpa", typePTR))
	f.Add(buildQuery(0x0001, "example.com", typeA)) // forwardable
	f.Add([]byte{0, 1})                             // shorter than a header
	f.Add(make([]byte, 12))                         // header only
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, req []byte) {
		resp, _ := l.handle(req)
		if resp == nil {
			return
		}
		if len(resp) > 512 {
			t.Fatalf("response %d bytes exceeds the 512-byte UDP cap on %x", len(resp), req)
		}
		if len(req) >= 2 && (resp[0] != req[0] || resp[1] != req[1]) {
			t.Fatalf("response txid %02x%02x != request %02x%02x", resp[0], resp[1], req[0], req[1])
		}
	})
}

// FuzzReadTCPMessage exercises the length-framed TCP reader on untrusted bytes -
// a 2-byte length prefix an attacker controls, followed by fewer or more bytes
// than promised. Invariants: never panic, and a successful read returns exactly
// the declared body length, at least a DNS header long.
func FuzzReadTCPMessage(f *testing.F) {
	f.Add([]byte{0x00, 0x0c, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) // header-sized body
	f.Add([]byte{0xff, 0xff})                                        // huge length, no body
	f.Add([]byte{0x00})                                              // truncated prefix
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, ok := readTCPMessage(bytes.NewReader(data))
		if !ok {
			return
		}
		if len(msg) < headerLen {
			t.Fatalf("accepted a %d-byte body under the %d header floor", len(msg), headerLen)
		}
		if len(data) < 2+len(msg) {
			t.Fatalf("returned %d bytes from only %d input bytes", len(msg), len(data))
		}
	})
}
