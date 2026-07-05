package dns

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildQuery assembles a plain uncompressed query for name/qtype.
func buildQuery(txid uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(txid >> 8), byte(txid), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	msg = append(msg, encodeName(name)...)
	return append(msg, byte(qtype>>8), byte(qtype), 0, classIN)
}

func testZone() *Zone {
	return NewZone(map[string]string{
		"bpx-19":  "10.0.0.42",
		"mcx-foh": "10.0.0.50",
	})
}

// respondVia runs one query through a fake listener in the given mode.
func respondVia(t *testing.T, mode Mode, z *Zone, query []byte) (resp, forward []byte) {
	t.Helper()
	srv := New("")
	srv.SetZone(z)
	l := &listener{srv: srv, mode: mode, bindIP: [4]byte{10, 0, 0, 1}}
	return l.handle(query)
}

func rcodeOf(resp []byte) byte  { return resp[3] & 0x0f }
func ancountOf(resp []byte) int { return int(resp[6])<<8 | int(resp[7]) }

// lastIPv4 extracts the final 4 bytes (the A rdata of a single-answer response).
func lastIPv4(resp []byte) net.IP { return net.IP(resp[len(resp)-4:]) }

func TestZoneAnswersBothSuffixes(t *testing.T) {
	z := testZone()
	for _, name := range []string{"bpx-19." + SuffixInv, "bpx-19." + SuffixDHCP} {
		resp, fwd := respondVia(t, ModeZone, z, buildQuery(0x1234, name, typeA))
		if fwd != nil {
			t.Fatalf("%s: forwarded instead of answered", name)
		}
		if rcodeOf(resp) != rcodeNoError || ancountOf(resp) != 1 {
			t.Fatalf("%s: rcode %d ancount %d", name, rcodeOf(resp), ancountOf(resp))
		}
		if got := lastIPv4(resp).String(); got != "10.0.0.42" {
			t.Fatalf("%s resolved to %s", name, got)
		}
		if resp[2]&0x04 == 0 {
			t.Fatalf("%s: AA not set on an authoritative answer", name)
		}
	}
}

func TestZoneApexAnswersPerSocket(t *testing.T) {
	resp, fwd := respondVia(t, ModeZone, testZone(), buildQuery(1, SuffixDHCP, typeA))
	if fwd != nil {
		t.Fatal("apex query forwarded")
	}
	if got := lastIPv4(resp).String(); got != "10.0.0.1" {
		t.Fatalf("apex resolved to %s, want the listener's own 10.0.0.1", got)
	}
}

func TestZoneNXDomainAndNoData(t *testing.T) {
	z := testZone()
	// Unknown name under an authoritative suffix: NXDOMAIN, never forwarded.
	resp, fwd := respondVia(t, ModeZone, z, buildQuery(2, "nope."+SuffixInv, typeA))
	if fwd != nil || rcodeOf(resp) != rcodeNXDomain {
		t.Fatalf("unknown zone name: fwd=%v rcode=%d", fwd != nil, rcodeOf(resp))
	}
	// Known name, AAAA: NOERROR with zero answers (NODATA) so clients fall back to A.
	resp, _ = respondVia(t, ModeZone, z, buildQuery(3, "bpx-19."+SuffixDHCP, 28))
	if rcodeOf(resp) != rcodeNoError || ancountOf(resp) != 0 {
		t.Fatalf("AAAA on known name: rcode=%d ancount=%d", rcodeOf(resp), ancountOf(resp))
	}
	// inv apex: exists, carries no records.
	resp, _ = respondVia(t, ModeZone, z, buildQuery(4, SuffixInv, typeA))
	if rcodeOf(resp) != rcodeNoError || ancountOf(resp) != 0 {
		t.Fatalf("inv apex: rcode=%d ancount=%d", rcodeOf(resp), ancountOf(resp))
	}
}

func TestZonePTRCanonical(t *testing.T) {
	resp, fwd := respondVia(t, ModeZone, testZone(), buildQuery(5, "42.0.0.10.in-addr.arpa", typePTR))
	if fwd != nil {
		t.Fatal("known PTR forwarded")
	}
	if rcodeOf(resp) != rcodeNoError || ancountOf(resp) != 1 {
		t.Fatalf("PTR: rcode=%d ancount=%d", rcodeOf(resp), ancountOf(resp))
	}
	want := encodeName("bpx-19." + SuffixDHCP)
	got := resp[len(resp)-len(want):]
	if string(got) != string(want) {
		t.Fatalf("PTR target %q, want canonical dhcp-suffix name", got)
	}
}

func TestDoHCanaryNXDomain(t *testing.T) {
	resp, fwd := respondVia(t, ModeZone, testZone(), buildQuery(6, dohCanary, typeA))
	if fwd != nil || rcodeOf(resp) != rcodeNXDomain {
		t.Fatalf("DoH canary: fwd=%v rcode=%d", fwd != nil, rcodeOf(resp))
	}
}

func TestRedirectModeAnswersEverything(t *testing.T) {
	resp, fwd := respondVia(t, ModeRedirect, nil, buildQuery(7, "captive.example.com", typeA))
	if fwd != nil {
		t.Fatal("redirect mode forwarded")
	}
	if got := lastIPv4(resp).String(); got != "10.0.0.1" {
		t.Fatalf("redirect answered %s, want the bind IP", got)
	}
}

func TestOutsideZoneIsForwarded(t *testing.T) {
	resp, fwd := respondVia(t, ModeZone, testZone(), buildQuery(8, "example.com", typeA))
	if resp != nil || fwd == nil {
		t.Fatal("outside-zone query was not handed to the forward path")
	}
}

func TestResponsesAreDropped(t *testing.T) {
	q := buildQuery(9, "example.com", typeA)
	q[2] |= 0x80 // QR: this is a response
	resp, fwd := respondVia(t, ModeZone, testZone(), q)
	if resp != nil || fwd != nil {
		t.Fatal("a QR=1 packet must be dropped, not answered or forwarded")
	}
}

func TestForwardVerifiedAgainstFakeUpstream(t *testing.T) {
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		buf := make([]byte, 1500)
		n, remote, err := up.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// First a spoof with the wrong txid, then the genuine answer.
		spoof := make([]byte, n)
		copy(spoof, buf[:n])
		spoof[0] ^= 0xff
		spoof[2] |= 0x80
		_, _ = up.WriteToUDP(spoof, remote)
		genuine := make([]byte, n)
		copy(genuine, buf[:n])
		genuine[2] |= 0x80
		_, _ = up.WriteToUDP(genuine, remote)
	}()

	query := buildQuery(0xbeef, "example.com", typeA)
	q, _ := parseQuestion(query)
	resp := forwardOne(query, q, up.LocalAddr().String())
	if resp == nil {
		t.Fatal("verified reply not returned")
	}
	if resp[0] != query[0] || resp[1] != query[1] {
		t.Fatal("returned the spoofed txid")
	}
}

func TestForwardIsolatedReturnsNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("# no nameservers\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := New(path)
	query := buildQuery(10, "example.com", typeA)
	q, _ := parseQuestion(query)
	if resp := srv.forward(query, q); resp != nil {
		t.Fatal("isolated forward returned a reply; the caller must SERVFAIL")
	}
}

func TestResolvConfParsingAndSelfExclusion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	body := "search lan\nnameserver 1.1.1.1\nnameserver 10.0.0.1\nnameserver not-an-ip\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := newResolvCache(path)
	got := rc.upstreams(map[string]bool{"10.0.0.1": true})
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("upstreams = %v, want [1.1.1.1] (self excluded, junk skipped)", got)
	}
}

func TestRateLimiterWindows(t *testing.T) {
	rl := rateLimiter{counts: map[string]int{}}
	base := time.Unix(1000, 0)
	for i := 0; i < queryLimitPerSec; i++ {
		if !rl.allow("10.0.0.9", base) {
			t.Fatalf("query %d refused under the limit", i)
		}
	}
	if rl.allow("10.0.0.9", base) {
		t.Fatal("over-limit query allowed")
	}
	if !rl.allow("10.0.0.8", base) {
		t.Fatal("an unrelated source was limited")
	}
	if !rl.allow("10.0.0.9", base.Add(time.Second)) {
		t.Fatal("limit did not reset on the next window")
	}
}

func TestZoneCapAndDeterminism(t *testing.T) {
	hosts := map[string]string{}
	for i := 0; i < maxZoneNames+50; i++ {
		hosts[fmtName(i)] = "10.0.0.9"
	}
	z1, z2 := NewZone(hosts), NewZone(hosts)
	if len(z1.a) != 2*maxZoneNames {
		t.Fatalf("zone holds %d records, want the %d cap x 2 suffixes", len(z1.a), maxZoneNames)
	}
	if len(z1.a) != len(z2.a) || z1.ptr[[4]byte{10, 0, 0, 9}] != z2.ptr[[4]byte{10, 0, 0, 9}] {
		t.Fatal("two builds of the same input differ")
	}
}

func fmtName(i int) string {
	const digits = "abcdefghij"
	out := []byte{'d'}
	for _, c := range []byte{byte(i / 1000 % 10), byte(i / 100 % 10), byte(i / 10 % 10), byte(i % 10)} {
		out = append(out, digits[c])
	}
	return string(out)
}

func TestOversizedAnswerGetsTC(t *testing.T) {
	// A maximal question name leaves no room once a bloated answer set is added.
	long := ""
	for i := 0; i < 4; i++ {
		long += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." // 63 octets
	}
	long += "x"
	query := buildQuery(11, long, typeA)
	q, ok := parseQuestion(query)
	if !ok {
		t.Fatal("long question did not parse")
	}
	big := make([][]byte, 40)
	for i := range big {
		big[i] = rrPTR(long, answerTTL)
	}
	resp := respond(query, q, rcodeNoError, true, big...)
	if len(resp) > maxUDPResponse {
		t.Fatalf("response %d bytes exceeds the UDP cap", len(resp))
	}
	if resp[2]&0x02 == 0 || ancountOf(resp) != 0 {
		t.Fatal("oversized answer not truncated with TC set")
	}
}

func TestStartStopLifecycle(t *testing.T) {
	// Binding :53 needs privilege; this only proves Stop() is safe repeatedly and
	// after a failed start (no listeners came up).
	srv := New("")
	srv.StartZone([]string{"203.0.113.250"}) // TEST-NET address: bind fails, logged, skipped
	srv.Stop()
	srv.Stop()
}
