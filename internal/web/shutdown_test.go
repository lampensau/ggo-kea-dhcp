package web

import (
	"runtime"
	"testing"
	"time"
)

// stopBackground must end AND JOIN the background loops so main's deferred
// sqlite.Close never races goroutines still issuing queries (every service
// restart and self-update hits this path). The join is the load-bearing part:
// signalling alone leaves a loop already past its select free to issue
// multi-statement work into the closing database.
func TestStopBackgroundJoinsLoops(t *testing.T) {
	s, _ := newTestServer(t)
	s.live = newLiveHub()
	s.health = newBackendHealth()
	s.metrics = newMetricsStore()

	before := runtime.NumGoroutine()
	s.startLiveTicker()
	s.startBackendHealthProbe()
	s.startUpdateCheckLoop()
	s.startClockWatch()
	s.kickUpdateCheck()
	// (startMetricsSampler shares the same wg+select pattern; its 15s boot
	// warmup makes it impractical to spin up here.)

	s.stopBackground()

	select {
	case <-s.bg.doneCh():
	default:
		t.Fatal("stopBackground did not close the done channel")
	}

	// stopBackground WAITED, so the loops must already be gone - no polling
	// grace beyond scheduler noise.
	deadline := time.Now().Add(500 * time.Millisecond)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines still running after stopBackground returned: %d > %d",
				runtime.NumGoroutine(), before)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
