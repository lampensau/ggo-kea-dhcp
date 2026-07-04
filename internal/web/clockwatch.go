package web

import (
	"fmt"
	"log"
	"os"
	"time"
)

// clockSyncStamp is systemd-timesyncd's "clock is disciplined" marker - it appears
// on first sync (the same signal the preflight clock check reads).
const clockSyncStamp = "/run/systemd/timesync/synchronized"

// clockStepThreshold is the wall-vs-monotonic divergence that counts as a real step
// rather than scheduler jitter (which moves both clocks together, so their
// difference stays near zero).
const clockStepThreshold = 2 * time.Second

// clockWatchInterval is the poll cadence. A ~30s detection latency is irrelevant
// for an after-the-fact audit record.
const clockWatchInterval = 30 * time.Second

// startClockWatch records system-clock discontinuities to the audit log. It exists
// because a stepped clock silently reclaims every DHCP lease whose expiry predates
// the step: an RTC-less box boots with a stale clock, devices lease under it, then
// NTP reconnects and jumps the clock days forward - and Kea's lease-file-cleanup
// purges the lot. Without this there is NO record of why the leases vanished; the
// audit entry makes that first-class and diagnosable after the fact.
//
// Detection is wall-vs-monotonic: the monotonic clock is immune to steps, so across
// a tick the difference between wall-elapsed and monotonic-elapsed IS the step
// magnitude. Polling (not a timerfd) keeps it pure-stdlib; the latency does not
// matter for an audit trail.
func (s *Server) startClockWatch() {
	go func() {
		last := time.Now()
		synced := clockDisciplined()
		t := time.NewTicker(clockWatchInterval)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			// Round(0) strips the monotonic reading, forcing wall-clock arithmetic;
			// the plain Sub uses the monotonic reading. Their difference is the
			// discontinuous step (signed: positive = clock jumped forward).
			step := now.Round(0).Sub(last.Round(0)) - now.Sub(last)
			if step > clockStepThreshold || step < -clockStepThreshold {
				s.auditClockStep(step)
			}
			last = now

			// First NTP sync: the stamp file's absent -> present transition.
			if !synced && clockDisciplined() {
				synced = true
				_ = s.sqlite.LogAudit("SYSTEM", "TIME_SYNCED", "system clock", "", "NTP synchronized - the clock is now disciplined", "INFO")
			}
		}
	}()
}

// clockDisciplined reports whether systemd-timesyncd has synchronized the clock.
func clockDisciplined() bool {
	_, err := os.Stat(clockSyncStamp)
	return err == nil
}

// clockStepDesc splits a signed step into a human direction and positive magnitude.
func clockStepDesc(step time.Duration) (dir string, mag time.Duration) {
	if step < 0 {
		return "backward", -step
	}
	return "forward", step
}

// auditClockStep records a discontinuous clock change, naming direction and
// magnitude so a lease-table wipe traceable to it is obvious in the log.
func (s *Server) auditClockStep(step time.Duration) {
	dir, mag := clockStepDesc(step)
	mag = mag.Round(time.Second)
	detail := fmt.Sprintf("system clock jumped %s by %s (NTP resync or manual set); DHCP leases whose expiry now lies in the past are reclaimed by Kea", dir, mag)
	log.Printf("[clock] step detected: %s %s", dir, mag)
	_ = s.sqlite.LogAudit("SYSTEM", "CLOCK_STEP", "system clock", "", detail, "WARNING")
}
