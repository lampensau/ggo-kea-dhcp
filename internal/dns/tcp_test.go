package dns

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// frame prefixes msg with its 2-byte length, matching writeTCPMessage's wire form.
func frame(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

func TestReadWriteTCPMessageRoundtrip(t *testing.T) {
	msg := buildQuery(0x1234, "example.com", typeA)
	var buf bytes.Buffer
	if !writeTCPMessage(&buf, msg) {
		t.Fatal("writeTCPMessage refused a normal message")
	}
	got, ok := readTCPMessage(&buf)
	if !ok || !bytes.Equal(got, msg) {
		t.Fatalf("roundtrip mismatch: ok=%v got=%x want=%x", ok, got, msg)
	}
}

func TestWriteTCPMessageRefusesOversize(t *testing.T) {
	if writeTCPMessage(io.Discard, make([]byte, 0x10000)) {
		t.Fatal("a message over 65535 bytes must be refused, not framed")
	}
}

func TestReadTCPMessageRejectsShortFrames(t *testing.T) {
	// A length prefix promising more than arrives: ReadFull must fail, not hang or
	// return a partial message.
	if _, ok := readTCPMessage(bytes.NewReader(frame([]byte("short")))); ok {
		// len("short")=5 < headerLen, so this is rejected on the size floor.
		t.Fatal("a body shorter than a DNS header was accepted")
	}
	// A prefix declaring 100 bytes but only 3 present.
	partial := []byte{0x00, 0x64, 0x01, 0x02, 0x03}
	if _, ok := readTCPMessage(bytes.NewReader(partial)); ok {
		t.Fatal("a truncated body was accepted")
	}
	// A truncated length prefix itself.
	if _, ok := readTCPMessage(bytes.NewReader([]byte{0x00})); ok {
		t.Fatal("a truncated length prefix was accepted")
	}
}

// fakeTCPUpstream answers one framed query with reply(query), then closes. It
// returns the listen address.
func fakeTCPUpstream(t *testing.T, reply func(req []byte) []byte) string {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		req, ok := readTCPMessage(conn)
		if !ok {
			return
		}
		writeTCPMessage(conn, reply(req))
	}()
	return ln.Addr().String()
}

func TestForwardOneTCPRelaysLargeAnswer(t *testing.T) {
	// The whole point of TCP: an answer larger than any UDP payload comes back
	// intact. Build a reply over 4096 bytes (the size the UDP path could never
	// deliver) by padding the answer section; parseQuestion only reads the header
	// and question, so the padding is a valid stand-in for a big RRset.
	const size = 5038
	up := fakeTCPUpstream(t, func(req []byte) []byte {
		reply := make([]byte, size)
		copy(reply, req) // header + question
		reply[2] |= 0x80 // QR
		return reply
	})

	query := buildQuery(0xbeef, "amazon.com", typeANY)
	q, _ := parseQuestion(query)
	resp := forwardOneTCP(query, q, up)
	if resp == nil {
		t.Fatal("large TCP answer was not relayed")
	}
	if len(resp) != size {
		t.Fatalf("relayed %d bytes, want the full %d", len(resp), size)
	}
	if resp[0] != query[0] || resp[1] != query[1] {
		t.Fatal("relayed reply has the wrong transaction id")
	}
}

func TestForwardOneTCPRejectsQuestionMismatch(t *testing.T) {
	// Correct txid but a different question name: a stale/spoofed reply that must
	// be rejected even over the connected TCP socket.
	up := fakeTCPUpstream(t, func(req []byte) []byte {
		reply := buildQuery(uint16(req[0])<<8|uint16(req[1]), "evil.example.net", typeA)
		reply[2] |= 0x80
		return reply
	})
	query := buildQuery(0xabcd, "example.com", typeA)
	q, _ := parseQuestion(query)
	if resp := forwardOneTCP(query, q, up); resp != nil {
		t.Fatal("a reply whose question did not match was accepted")
	}
}

// TestServeTCPEndToEnd binds a real TCP listener on an unprivileged port and
// drives it like a client whose UDP answer was truncated: connect, send a framed
// query for a device-zone name, read the framed answer, then reuse the same
// connection for a second query (RFC 7766).
func TestServeTCPEndToEnd(t *testing.T) {
	srv := New("")
	srv.SetZone(testZone())
	srv.port = freePort(t)
	if failed := srv.StartZone([]string{"127.0.0.1"}); len(failed) != 0 {
		t.Fatalf("listener failed to bind: %v", failed)
	}
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.port)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	for i, txid := range []uint16{0x0001, 0x0002} {
		if !writeTCPMessage(conn, buildQuery(txid, "bpx-19."+SuffixInv, typeA)) {
			t.Fatalf("query %d: write failed", i)
		}
		resp, ok := readTCPMessage(conn)
		if !ok {
			t.Fatalf("query %d: no framed answer (connection not reused?)", i)
		}
		if resp[0] != byte(txid>>8) || resp[1] != byte(txid) {
			t.Fatalf("query %d: answer txid mismatch", i)
		}
		if rcodeOf(resp) != rcodeNoError || ancountOf(resp) != 1 {
			t.Fatalf("query %d: rcode=%d ancount=%d", i, rcodeOf(resp), ancountOf(resp))
		}
		if got := lastIPv4(resp).String(); got != "10.0.0.42" {
			t.Fatalf("query %d: resolved to %s, want 10.0.0.42", i, got)
		}
	}
}

// freePort grabs an unused TCP port by binding :0 and releasing it. Good enough
// for a test; a race with another binder is vanishingly unlikely on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestRebindMissingHealsUDPOnlyTCPHalf pins #163: a listener that came up UDP-only
// (its best-effort TCP bind lost to a squatter) must have its TCP half re-bound by
// RebindMissing once :53/tcp frees, not stay UDP-only for the process lifetime.
func TestRebindMissingHealsUDPOnlyTCPHalf(t *testing.T) {
	srv := New("")
	srv.SetZone(testZone())
	port := freePort(t)
	srv.port = port

	// Squat TCP/port so StartZone's TCP bind fails while UDP still binds.
	squat, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if failed := srv.StartZone([]string{"127.0.0.1"}); len(failed) != 0 {
		t.Fatalf("UDP listener should still bind under a TCP-only squatter: %v", failed)
	}
	defer srv.Stop()
	if srv.listeners[0].tcpLn != nil {
		t.Fatal("precondition: TCP bind should have failed under the squatter")
	}

	// TCP still squatted: nothing to heal.
	if healed := srv.RebindMissing(); len(healed) != 0 {
		t.Fatalf("RebindMissing healed %v while TCP was still squatted", healed)
	}

	// Free the port; RebindMissing must now late-bind the TCP half.
	_ = squat.Close()
	if healed := srv.RebindMissing(); len(healed) != 1 || healed[0] != "127.0.0.1" {
		t.Fatalf("RebindMissing = %v, want [127.0.0.1] once TCP is free", healed)
	}
	if srv.listeners[0].tcpLn == nil {
		t.Fatal("TCP half not bound after heal")
	}

	// The healed TCP half actually serves a framed query.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if !writeTCPMessage(conn, buildQuery(0x1234, "bpx-19."+SuffixInv, typeA)) {
		t.Fatal("write to healed TCP listener failed")
	}
	resp, ok := readTCPMessage(conn)
	if !ok || rcodeOf(resp) != rcodeNoError || ancountOf(resp) != 1 {
		t.Fatalf("healed TCP listener did not answer: ok=%v", ok)
	}
}
