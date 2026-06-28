package netmon

import "sync"

// Sniffer yields captured frames for one interface and is torn down on Close.
// afpacketSniffer (real, sniffer_linux.go) and nopSniffer (dev-mode) implement
// it; FakeSniffer is the host-free test double. The monitor selects over
// Frames() and its own quit/tick, so a sniffer that never produces (nopSniffer)
// still lets the monitor tick and emit snapshots.
type Sniffer interface {
	Frames() <-chan Frame
	Close() error
}

// nopSniffer is the dev-sandbox / unavailable sniffer: it yields no frames and
// closes cleanly. openCapture returns it (after a [Dev Mode] log) on EPERM/ENODEV,
// mirroring SudoCommander's toolPresent bypass. The monitor type-asserts for it to
// mark the interface Available=false on the card.
type nopSniffer struct {
	ch        chan Frame
	closeOnce sync.Once
}

func newNopSniffer() *nopSniffer { return &nopSniffer{ch: make(chan Frame)} }

func (n *nopSniffer) Frames() <-chan Frame { return n.ch }

// Close honors the same channel-close contract as afpacketSniffer: a consumer
// ranging over Frames() (TrunkProbe.loop) must observe the channel close to
// return, or its Stop()'s wg.Wait() deadlocks. closeOnce guards the double-close
// possible between an explicit Stop() and Monitor.serveOnce's deferred close.
func (n *nopSniffer) Close() error { n.closeOnce.Do(func() { close(n.ch) }); return nil }

// isNop reports whether s is the dev-mode no-op sniffer (no socket available).
func isNop(s Sniffer) bool {
	_, ok := s.(*nopSniffer)
	return ok
}
