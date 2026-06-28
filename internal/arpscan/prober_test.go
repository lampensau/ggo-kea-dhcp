package arpscan

import (
	"sync"
	"testing"
	"time"
)

// fakeTransport is an in-memory Transport: it records sent frames and lets a test feed
// "received" ARP frames; Receive blocks until fed or closed.
type fakeTransport struct {
	sent      chan []byte
	recv      chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{sent: make(chan []byte, 64), recv: make(chan []byte, 64), closed: make(chan struct{})}
}

func (f *fakeTransport) Send(frame []byte) error {
	cp := append([]byte(nil), frame...)
	select {
	case f.sent <- cp:
	default:
	}
	return nil
}

func (f *fakeTransport) Receive() ([]byte, bool) {
	select {
	case frame := <-f.recv:
		return frame, true
	case <-f.closed:
		return nil, false
	}
}

func (f *fakeTransport) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeTransport) feed(frame []byte) { f.recv <- frame }

func waitFor(t *testing.T, what string, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// errFirstTransport errors on the first Send and succeeds thereafter, recording every
// target IP it was asked to probe so a test can assert the cycle was not abandoned.
type errFirstTransport struct {
	mu      sync.Mutex
	calls   int
	targets [][4]byte
	closed  chan struct{}
}

func newErrFirstTransport() *errFirstTransport {
	return &errFirstTransport{closed: make(chan struct{})}
}

func (e *errFirstTransport) Send(frame []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	if e.calls == 1 {
		return errOpen // transient failure on the first IP of the cycle
	}
	var ip [4]byte
	copy(ip[:], frame[38:42]) // target protocol address
	e.targets = append(e.targets, ip)
	return nil
}

func (e *errFirstTransport) Receive() ([]byte, bool) { <-e.closed; return nil, false }

func (e *errFirstTransport) Close() error { close(e.closed); return nil }

func (e *errFirstTransport) sent() [][4]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][4]byte(nil), e.targets...)
}

// TestProbeOnceContinuesPastSendError proves a transient Send error on one lease IP does
// NOT abandon the rest of the probe cycle: the remaining IPs are still probed, so a single
// buffer-pressure error can't flip every other leased device offline.
func TestProbeOnceContinuesPastSendError(t *testing.T) {
	et := newErrFirstTransport()
	p := newProberWithOpen(func(Spec) (Transport, error) { return et, nil })
	p.Start([]Spec{{
		Iface:    "eth0",
		SrcIP:    [4]byte{10, 0, 0, 1},
		SrcMAC:   [6]byte{0x02, 0, 0, 0, 0, 0x01},
		LeaseIPs: func() []string { return []string{"10.0.0.20", "10.0.0.21", "10.0.0.22"} },
	}})
	defer p.Stop()

	// The first Send errors (.20); .21 and .22 must still be sent in the same cycle.
	waitFor(t, "remaining IPs probed after a send error", func() bool { return len(et.sent()) >= 2 })
	got := et.sent()
	want := map[[4]byte]bool{{10, 0, 0, 21}: true, {10, 0, 0, 22}: true}
	for _, ip := range got {
		delete(want, ip)
	}
	if len(want) != 0 {
		t.Fatalf("after a first-IP send error, expected .21 and .22 still probed; got %v", got)
	}
}

func TestBuildAndParseARP(t *testing.T) {
	srcMAC := [6]byte{0x02, 0, 0, 0, 0, 0x01}
	req := buildARPRequest(srcMAC, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 20})
	if len(req) != 42 {
		t.Fatalf("ARP request len = %d, want 42", len(req))
	}
	// Broadcast dst, ARP ethertype, request opcode, target IP in place.
	for i := 0; i < 6; i++ {
		if req[i] != 0xff {
			t.Fatal("dst must be broadcast")
		}
	}
	if req[12] != 0x08 || req[13] != 0x06 {
		t.Fatal("ethertype must be ARP")
	}
	if req[21] != arpOpRequest {
		t.Fatal("opcode must be request")
	}
	if req[38] != 10 || req[39] != 0 || req[40] != 0 || req[41] != 20 {
		t.Fatal("target protocol address must be 10.0.0.20")
	}
	// parseARPSender reads the SENDER address (here 10.0.0.1).
	if ip, _, ok := parseARPSender(req); !ok || ip != [4]byte{10, 0, 0, 1} {
		t.Fatalf("parseARPSender = %v ok=%v, want 10.0.0.1", ip, ok)
	}
	// A non-ARP frame is rejected.
	bad := make([]byte, 42)
	bad[12], bad[13] = 0x08, 0x00 // IPv4
	if _, _, ok := parseARPSender(bad); ok {
		t.Fatal("non-ARP frame must not parse")
	}
}

func TestReachTrackerAging(t *testing.T) {
	tr := newReachTracker()
	base := time.Unix(1000, 0)
	tr.record([4]byte{10, 0, 0, 20}, base)
	if !tr.within(base.Add(reachWindow - time.Second))["10.0.0.20"] {
		t.Fatal("should be reachable within the window")
	}
	if tr.within(base.Add(reachWindow + time.Second))["10.0.0.20"] {
		t.Fatal("should age out past the window")
	}
}

// TestProberProbesAndRecordsReply drives the full loop with a fake transport: the prober
// must broadcast a who-has for the lease IP, and a simulated reply must mark that IP
// online; Available reflects a successfully-opened transport.
func TestProberProbesAndRecordsReply(t *testing.T) {
	ft := newFakeTransport()
	p := newProberWithOpen(func(Spec) (Transport, error) { return ft, nil })
	p.Start([]Spec{{
		Iface:    "eth0",
		SrcIP:    [4]byte{10, 0, 0, 1},
		SrcMAC:   [6]byte{0x02, 0, 0, 0, 0, 0x01},
		LeaseIPs: func() []string { return []string{"10.0.0.20"} },
	}})
	defer p.Stop()

	// A who-has for 10.0.0.20 is broadcast immediately.
	select {
	case sent := <-ft.sent:
		if sent[38] != 10 || sent[41] != 20 {
			t.Fatalf("probed wrong target: % x", sent[38:42])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no probe was sent")
	}

	if p.Snapshot().ReachableIPs["10.0.0.20"] {
		t.Fatal("must not be online before any reply")
	}
	if !p.Snapshot().Available {
		t.Fatal("Available should be true once a transport opened")
	}

	// The device answers (sender = 10.0.0.20). recvLoop records it.
	ft.feed(buildARPRequest([6]byte{0x00, 0x1f, 0x80, 0x20, 0xaa, 0xbb}, [4]byte{10, 0, 0, 20}, [4]byte{10, 0, 0, 1}))
	waitFor(t, "10.0.0.20 online", func() bool { return p.Snapshot().ReachableIPs["10.0.0.20"] })
}

// TestProberUnavailableWhenOpenFails proves a no-CAP_NET_RAW / dev-sandbox box degrades
// to Available=false (no dots) instead of crashing.
func TestProberUnavailableWhenOpenFails(t *testing.T) {
	p := newProberWithOpen(func(Spec) (Transport, error) { return nil, errOpen })
	p.Start([]Spec{{Iface: "eth0", LeaseIPs: func() []string { return nil }}})
	defer p.Stop()
	if p.Snapshot().Available {
		t.Fatal("Available should be false when no transport opens")
	}
}

// TestProbeHostReturnsResponderMAC proves an on-demand probe sends a who-has for the
// target and returns the MAC of the device that answers - the live-conflict signal the
// reservation/pin handlers use to refuse re-IP'ing onto another device's address.
func TestProbeHostReturnsResponderMAC(t *testing.T) {
	ft := newFakeTransport()
	p := newProberWithOpen(func(Spec) (Transport, error) { return ft, nil })
	p.Start([]Spec{{
		Iface:    "eth0",
		SrcIP:    [4]byte{10, 0, 0, 1},
		SrcMAC:   [6]byte{0x02, 0, 0, 0, 0, 0x01},
		LeaseIPs: func() []string { return nil }, // no background probes to interleave
	}})
	defer p.Stop()

	respMAC := [6]byte{0x00, 0x1f, 0x80, 0x20, 0xaa, 0xbb}
	go func() {
		select {
		case <-ft.sent: // the ProbeHost who-has went out
			ft.feed(buildARPRequest(respMAC, [4]byte{10, 0, 0, 50}, [4]byte{10, 0, 0, 1}))
		case <-time.After(2 * time.Second):
		}
	}()

	mac, alive := p.ProbeHost("10.0.0.50")
	if !alive {
		t.Fatal("expected the probed host to be reported alive")
	}
	if mac != "00:1f:80:20:aa:bb" {
		t.Fatalf("responder MAC = %q, want 00:1f:80:20:aa:bb", mac)
	}
}

// TestProbeHostUnknownWhenUnavailable proves a box with no capture socket reports
// not-alive (liveness UNKNOWN) so the caller does not block a reservation.
func TestProbeHostUnknownWhenUnavailable(t *testing.T) {
	p := newProberWithOpen(func(Spec) (Transport, error) { return nil, errOpen })
	p.Start([]Spec{{Iface: "eth0", LeaseIPs: func() []string { return nil }}})
	defer p.Stop()
	if _, alive := p.ProbeHost("10.0.0.50"); alive {
		t.Fatal("ProbeHost must report not-alive when probing is unavailable")
	}
}

// TestProbeHostNoReply proves a probe for a silent address returns not-alive after the
// timeout (so a free address is reservable).
func TestProbeHostNoReply(t *testing.T) {
	ft := newFakeTransport()
	p := newProberWithOpen(func(Spec) (Transport, error) { return ft, nil })
	p.Start([]Spec{{Iface: "eth0", SrcIP: [4]byte{10, 0, 0, 1}, SrcMAC: [6]byte{0x02, 0, 0, 0, 0, 0x01}, LeaseIPs: func() []string { return nil }}})
	defer p.Stop()
	if _, alive := p.ProbeHost("10.0.0.77"); alive {
		t.Fatal("a silent address must report not-alive")
	}
}

var errOpen = &openErr{}

type openErr struct{}

func (*openErr) Error() string { return "open failed" }
