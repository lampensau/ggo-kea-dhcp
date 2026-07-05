package web

import (
	"runtime"
	"testing"
	"time"
)

// stopBackground must end the background ticker loops so main's deferred
// sqlite.Close never races goroutines still issuing queries (every service
// restart and self-update hits this path).
func TestStopBackgroundEndsTickerLoops(t *testing.T) {
	s, _ := newTestServer(t)
	s.done = make(chan struct{})
	s.live = newLiveHub()
	s.health = newBackendHealth()
	s.metrics = newMetricsStore()

	before := runtime.NumGoroutine()
	s.startLiveTicker()
	s.startBackendHealthProbe()
	s.startUpdateCheckLoop()
	// (startMetricsSampler is covered by the same select pattern; its 15s boot
	// warmup makes it impractical to spin up here.)

	s.stopBackground()

	select {
	case <-s.done:
	default:
		t.Fatal("stopBackground did not close the done channel")
	}

	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("ticker goroutines still running after stopBackground: %d > %d",
				runtime.NumGoroutine(), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
