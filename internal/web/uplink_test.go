package web

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestProbeGatewayRetry pins the anti-flap retry (issue #3): one failed dial is
// retried before the sample reads offline, a refused connection counts as
// reachable, and two failures are genuinely offline.
func TestProbeGatewayRetry(t *testing.T) {
	timeout := errors.New("dial timeout")

	// First dial lost, second answers: online (WiFi single-packet loss).
	calls := 0
	rtt := probeGateway("192.0.2.1", func(_, _ string, _ time.Duration) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, timeout
		}
		c, s := net.Pipe()
		_ = s.Close()
		return c, nil
	})
	if rtt < 0 || calls != 2 {
		t.Errorf("retry path: rtt=%d calls=%d, want online after 2 dials", rtt, calls)
	}

	// Connection refused proves reachability immediately - no retry.
	calls = 0
	rtt = probeGateway("192.0.2.1", func(_, _ string, _ time.Duration) (net.Conn, error) {
		calls++
		return nil, syscall.ECONNREFUSED
	})
	if rtt < 0 || calls != 1 {
		t.Errorf("refused path: rtt=%d calls=%d, want online after 1 dial", rtt, calls)
	}

	// Both dials fail: offline.
	calls = 0
	rtt = probeGateway("192.0.2.1", func(_, _ string, _ time.Duration) (net.Conn, error) {
		calls++
		return nil, timeout
	})
	if rtt != -1 || calls != 2 {
		t.Errorf("offline path: rtt=%d calls=%d, want -1 after 2 dials", rtt, calls)
	}
}
