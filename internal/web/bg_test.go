package web

import (
	"sync"
	"testing"
)

// wait joins the currently registered goroutines without signalling shutdown, so a
// test can await a dispatched background check and keep using the runner. Test-only:
// production always joins through stop, which is why this lives here and not in bg.go.
func (b *bgRunner) wait() { b.wg.Wait() }

// TestBgRunnerRefusesAddAfterStop pins the gate every background dispatcher relies
// on: once stop has begun, add must refuse rather than register a goroutine the
// join has already waited for. Callers act on ok to decide whether to spawn at all,
// so a silent true here would let a loop keep querying a closing database.
func TestBgRunnerRefusesAddAfterStop(t *testing.T) {
	b := newBgRunner()

	done, ok := b.add()
	if !ok {
		t.Fatal("add before stop must register")
	}
	done()

	b.stop()

	if _, ok := b.add(); ok {
		t.Fatal("add after stop must refuse: the join is already past its Wait")
	}
	select {
	case <-b.doneCh():
	default:
		t.Fatal("stop must close doneCh so the loops exit at their next select")
	}
}

// TestBgRunnerStopIsIdempotent covers the second-caller path: stopBackground can run
// from the shutdown handler and again from a test cleanup, and a second close(done)
// would panic.
func TestBgRunnerStopIsIdempotent(t *testing.T) {
	b := newBgRunner()
	b.stop()
	b.stop() // must not panic on a re-close of done
}

// TestBgRunnerAddStopRace hammers registration against shutdown under -race. The
// invariant the type exists for: a registration either lands before stop's Wait or
// is refused, never Add-ing onto a zero-counter WaitGroup that Wait already passed
// (the documented misuse). Registered work must also outlive the start of stop, so
// the join is real rather than a Wait on an already-drained counter: the accepted
// goroutines block on release, which is closed only after stop() has been entered
// (from a separate goroutine, since stop blocks in Wait until they finish).
func TestBgRunnerAddStopRace(t *testing.T) {
	for range 50 { // repeat: the race window is narrow, one pass proves little
		b := newBgRunner()
		release := make(chan struct{})

		var spawned sync.WaitGroup
		var accepted, refused int64
		var mu sync.Mutex

		for range 8 {
			spawned.Add(1)
			go func() {
				defer spawned.Done()
				done, ok := b.add()
				mu.Lock()
				if ok {
					accepted++
				} else {
					refused++
				}
				mu.Unlock()
				if !ok {
					return
				}
				// Registered work that outlives the start of stop: if stop's Wait did
				// not cover this goroutine, -race and the join below would notice.
				go func() {
					defer done()
					<-release
				}()
			}()
		}

		stopped := make(chan struct{})
		entered := make(chan struct{})
		go func() {
			defer close(stopped)
			close(entered)
			b.stop() // blocks in Wait until the accepted goroutines return
		}()
		go func() {
			<-entered      // stop is now running (or about to): its Wait must cover them
			close(release) // only now may the registered work finish
		}()

		spawned.Wait()
		<-stopped

		mu.Lock()
		total := accepted + refused
		mu.Unlock()
		if total != 8 {
			t.Fatalf("every registration must resolve exactly once: got %d of 8", total)
		}
		if _, ok := b.add(); ok {
			t.Fatal("add must refuse once stop has returned")
		}
	}
}

// TestBgRunnerWaitJoinsWithoutStopping guards the test-only wait() seam: it joins the
// registered goroutines but leaves the runner usable, unlike stop.
func TestBgRunnerWaitJoinsWithoutStopping(t *testing.T) {
	b := newBgRunner()

	ran := make(chan struct{})
	done, ok := b.add()
	if !ok {
		t.Fatal("add on a fresh runner must register")
	}
	go func() {
		defer done()
		close(ran)
	}()

	b.wait()
	select {
	case <-ran:
	default:
		t.Fatal("wait returned before the registered goroutine ran")
	}

	if _, ok := b.add(); !ok {
		t.Fatal("wait must not begin shutdown: add still has to register afterwards")
	}
	select {
	case <-b.doneCh():
		t.Fatal("wait must not close doneCh")
	default:
	}
}
