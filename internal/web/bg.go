package web

import "sync"

// bgRunner owns the shutdown-join discipline for the appliance's background
// goroutines (live ticker, metrics sampler, MariaDB probe, update check + kicked
// checks + result watcher, clock watch). done is closed on shutdown to end those
// loops before main's deferred sqlite.Close runs - otherwise they keep querying a
// closing database on every service restart and self-update. wg counts the
// goroutines so stop can JOIN them: signalling alone leaves a loop already past
// its select free to issue multi-statement work into the closing database.
//
// mu + stopping order wg.Add against stop's Wait: a registration racing shutdown
// (kickUpdateCheck fires from reconcile goroutines the join does not cover) must
// either land before the Wait or be refused - Add concurrent with a zero-counter
// Wait is the documented WaitGroup misuse. stopping also makes stop idempotent.
type bgRunner struct {
	done     chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	stopping bool
}

func newBgRunner() *bgRunner {
	return &bgRunner{done: make(chan struct{})}
}

// doneCh returns the channel closed when shutdown begins; background loops select
// on it to exit at their next iteration.
func (b *bgRunner) doneCh() <-chan struct{} { return b.done }

// add registers one goroutine with the shutdown join and returns its completion
// callback (defer it at the top of the goroutine). ok is false once shutdown has
// begun - the caller must then NOT start the goroutine, since the join is already
// waiting. Every registration goes through here so no caller has to remember the
// old bare-Add-vs-refuse distinction; the ones fired from goroutines the join does
// not cover (kickUpdateCheck, the SSE-handler load check, the update-result
// watchers) simply act on ok.
func (b *bgRunner) add() (done func(), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopping {
		return nil, false
	}
	b.wg.Add(1)
	return b.wg.Done, true
}

// wait joins the currently registered goroutines WITHOUT signalling shutdown, so a
// test can await a dispatched background check and then keep using the runner. Not
// a shutdown path: production always joins through stop.
func (b *bgRunner) wait() { b.wg.Wait() }

// stop signals shutdown and joins every registered goroutine. Closing done ends
// the loops at their next select; the Wait joins them - a loop already mid-body
// finishes it first (each body is bounded: opCtx on the Kea/DB calls, the
// Commander timeout on shell-outs), so the join is bounded too, well inside
// systemd's stop timeout. Idempotent: a second caller is a no-op.
func (b *bgRunner) stop() {
	b.mu.Lock()
	if b.stopping {
		b.mu.Unlock()
		return // idempotent: a second caller must not close(done) again
	}
	b.stopping = true
	close(b.done)
	b.mu.Unlock()
	b.wg.Wait()
}
