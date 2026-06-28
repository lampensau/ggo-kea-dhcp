package arpscan

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// timeoutTransport models the real SO_RCVTIMEO socket added by the hang fix:
// Receive() returns (nil, true) "timeout ticks" while the link is silent, a real
// frame when one is fed, and (nil, false) only once the transport is closed. This
// is exactly the contract afpacketTransport.Receive now honors (EAGAIN/EWOULDBLOCK/
// EINTR -> (nil,true); fd-closed -> (nil,false)), so recvLoop's nil-skip + quit-check
// control flow is exercised here without a raw socket.
type timeoutTransport struct {
	frames    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	recvCalls int64 // atomic: number of Receive() entries (proves it kept looping)
	tick      time.Duration
}

func newTimeoutTransport() *timeoutTransport {
	return &timeoutTransport{
		frames: make(chan []byte, 8),
		closed: make(chan struct{}),
		tick:   2 * time.Millisecond, // a fast stand-in for the real 250ms SO_RCVTIMEO
	}
}

func (t *timeoutTransport) Send([]byte) error { return nil }

func (t *timeoutTransport) Receive() ([]byte, bool) {
	atomic.AddInt64(&t.recvCalls, 1)
	select {
	case <-t.closed:
		return nil, false // fd closed (Stop) -> end recvLoop
	case fr := <-t.frames:
		return fr, true // a real ARP frame
	case <-time.After(t.tick):
		return nil, true // idle timeout tick: no frame, socket alive - keep looping
	}
}

func (t *timeoutTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func (t *timeoutTransport) feed(fr []byte) { t.frames <- fr }
func (t *timeoutTransport) calls() int64   { return atomic.LoadInt64(&t.recvCalls) }

// nilFalseTransport's Receive always returns (nil, false) immediately, modelling a
// permanently-faulted/closed socket. recvLoop must exit on the first such read and
// must NOT record a phantom IP from the nil frame.
type nilFalseTransport struct {
	recvCalls int64 // atomic
	closed    chan struct{}
	closeOnce sync.Once
}

func newNilFalseTransport() *nilFalseTransport {
	return &nilFalseTransport{closed: make(chan struct{})}
}

func (t *nilFalseTransport) Send([]byte) error { return nil }

func (t *nilFalseTransport) Receive() ([]byte, bool) {
	atomic.AddInt64(&t.recvCalls, 1)
	return nil, false
}

func (t *nilFalseTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func (t *nilFalseTransport) calls() int64 { return atomic.LoadInt64(&t.recvCalls) }

// TestRecvLoopSkipsTimeoutTicksThenRecordsRealFrame proves the nil-frame skip: a
// stream of (nil,true) timeout ticks records nothing (no phantom IPs), the prober
// stays Available, and a real ARP frame fed afterwards IS recorded - i.e. recvLoop
// neither exits on a timeout tick nor spin-records nil frames.
func TestRecvLoopSkipsTimeoutTicksThenRecordsRealFrame(t *testing.T) {
	tt := newTimeoutTransport()
	p := newProberWithOpen(func(Spec) (Transport, error) { return tt, nil })
	p.Start([]Spec{{
		Iface:    "eth0",
		SrcIP:    [4]byte{10, 0, 0, 1},
		SrcMAC:   [6]byte{0x02, 0, 0, 0, 0, 0x01},
		LeaseIPs: func() []string { return nil }, // no send noise: isolate recvLoop
	}})
	defer p.Stop()

	if !p.Snapshot().Available {
		t.Fatal("Available should be true once the transport opened")
	}

	// Let many timeout ticks pass; the loop must keep going but record nothing.
	waitFor(t, "recvLoop to keep looping over timeout ticks", func() bool { return tt.calls() >= 3 })
	if got := len(p.Snapshot().ReachableIPs); got != 0 {
		t.Fatalf("timeout ticks must not record any IP; got %d reachable", got)
	}

	// A real device reply arrives; recvLoop records its sender (10.0.0.20).
	tt.feed(buildARPRequest([6]byte{0x00, 0x1f, 0x80, 0x20, 0xaa, 0xbb}, [4]byte{10, 0, 0, 20}, [4]byte{10, 0, 0, 1}))
	waitFor(t, "10.0.0.20 recorded after a real frame past the timeout ticks",
		func() bool { return p.Snapshot().ReachableIPs["10.0.0.20"] })
}

// TestRecvLoopExitsOnNilFalse proves a (nil,false) read ends recvLoop at once and
// records no phantom IP from the nil frame. Stop must still be bounded (sendLoop is
// torn down by quit).
func TestRecvLoopExitsOnNilFalse(t *testing.T) {
	tt := newNilFalseTransport()
	p := newProberWithOpen(func(Spec) (Transport, error) { return tt, nil })
	p.Start([]Spec{{
		Iface:    "eth0",
		SrcIP:    [4]byte{10, 0, 0, 1},
		SrcMAC:   [6]byte{0x02, 0, 0, 0, 0, 0x01},
		LeaseIPs: func() []string { return nil },
	}})

	// recvLoop should have read exactly once (or a small bounded number) and exited;
	// crucially it must not spin-record a nil frame as a reachable IP.
	waitFor(t, "recvLoop to read once", func() bool { return tt.calls() >= 1 })
	if got := len(p.Snapshot().ReachableIPs); got != 0 {
		t.Fatalf("a (nil,false) read must not record an IP; got %d reachable", got)
	}

	mustReturnWithin(t, "Prober.Stop after recvLoop already exited", 2*time.Second, p.Stop)
}

// TestProberStopBoundedWithTimeoutOnlySocket is the core anti-hang assertion: with a
// socket that only ever ticks (never delivers a frame, never self-closes), Stop()
// must still return promptly. This is the unit-level proof of the SO_RCVTIMEO fix -
// Stop() closes quit AND closes the transport, so Receive() returns (nil,false) and
// recvLoop's wg.Wait() unblocks within a tick instead of hanging on a silent link.
func TestProberStopBoundedWithTimeoutOnlySocket(t *testing.T) {
	tt := newTimeoutTransport()
	p := newProberWithOpen(func(Spec) (Transport, error) { return tt, nil })
	p.Start([]Spec{{
		Iface:    "eth0",
		SrcIP:    [4]byte{10, 0, 0, 1},
		SrcMAC:   [6]byte{0x02, 0, 0, 0, 0, 0x01},
		LeaseIPs: func() []string { return []string{"10.0.0.20", "10.0.0.21"} },
	}})

	// Make sure both loops are actually running (a tick has been observed) before we
	// time the Stop, so the test proves Stop interrupts a live, blocked-in-Receive loop.
	waitFor(t, "runner to be live", func() bool { return tt.calls() >= 1 })
	mustReturnWithin(t, "Prober.Stop with a timeout-only socket", 2*time.Second, p.Stop)
}

// TestProberStopIdempotentAndBounded proves Stop is safe to call with no runners and
// to call twice - the reconciler calls Start (which calls Stop) on every ACTIVE entry.
func TestProberStopIdempotentAndBounded(t *testing.T) {
	p := newProberWithOpen(func(Spec) (Transport, error) { return newTimeoutTransport(), nil })

	mustReturnWithin(t, "Stop before any Start", time.Second, p.Stop) // no runners

	p.Start([]Spec{{Iface: "eth0", LeaseIPs: func() []string { return nil }}})
	mustReturnWithin(t, "first Stop", 2*time.Second, p.Stop)
	mustReturnWithin(t, "second Stop (idempotent)", time.Second, p.Stop)

	if p.Snapshot().Available {
		t.Fatal("Available must be false after Stop tore down all runners")
	}
}

// TestProberRestartAfterTimeoutStop proves Start is re-runnable after a Stop on a
// timeout-only socket (the reconciler's idempotent ACTIVE-entry contract): a second
// Start opens a fresh runner and a reply on it is recorded.
func TestProberRestartAfterTimeoutStop(t *testing.T) {
	var openCount int64
	open := func(Spec) (Transport, error) {
		atomic.AddInt64(&openCount, 1)
		return newTimeoutTransport(), nil
	}
	p := newProberWithOpen(open)
	spec := Spec{Iface: "eth0", SrcIP: [4]byte{10, 0, 0, 1}, SrcMAC: [6]byte{0x02, 0, 0, 0, 0, 0x01}, LeaseIPs: func() []string { return nil }}

	p.Start([]Spec{spec})
	mustReturnWithin(t, "Stop between starts", 2*time.Second, p.Stop)
	p.Start([]Spec{spec}) // Start() calls Stop() internally first, then re-opens
	defer p.Stop()

	if got := atomic.LoadInt64(&openCount); got < 2 {
		t.Fatalf("expected the transport reopened on restart; opens=%d", got)
	}
	if !p.Snapshot().Available {
		t.Fatal("Available should be true after the restart opened a fresh socket")
	}
}

// mustReturnWithin runs fn in a goroutine and fails the test if it does not return
// within d - so a hanging Stop/recvLoop fails the test instead of hanging the suite.
func mustReturnWithin(t *testing.T, what string, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v (deadlock/hang)", what, d)
	}
}
