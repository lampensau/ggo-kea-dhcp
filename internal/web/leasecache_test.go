package web

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/kea"
)

// TestLeaseCacheTTL pins the read-through contract: calls within maxAge share
// one fetch, a call past it refreshes, and maxAge 0 always polls (the sampler's
// RTT priming and the post-mutation publishes).
func TestLeaseCacheTTL(t *testing.T) {
	var fetches atomic.Int32
	now := time.Unix(1000, 0)
	c := newLeaseCache(func(ctx context.Context) ([]kea.ActiveLease, error) {
		fetches.Add(1)
		return []kea.ActiveLease{{IPAddress: "10.0.0.5"}}, nil
	})
	c.now = func() time.Time { return now }

	for range 5 {
		if _, err := c.get(context.Background(), leaseSrcTTL); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("5 reads within the TTL cost %d fetches, want 1", n)
	}

	now = now.Add(leaseSrcTTL + time.Second)
	if _, err := c.get(context.Background(), leaseSrcTTL); err != nil {
		t.Fatalf("get after TTL: %v", err)
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("stale read cost %d total fetches, want 2", n)
	}

	if _, err := c.get(context.Background(), 0); err != nil {
		t.Fatalf("forced get: %v", err)
	}
	if n := fetches.Load(); n != 3 {
		t.Fatalf("forced read cost %d total fetches, want 3 (maxAge 0 must poll)", n)
	}
}

// TestLeaseCacheSingleFlight pins that concurrent callers during a refresh
// share ONE round-trip - the stampede the cache exists to prevent.
func TestLeaseCacheSingleFlight(t *testing.T) {
	var fetches atomic.Int32
	release := make(chan struct{})
	c := newLeaseCache(func(ctx context.Context) ([]kea.ActiveLease, error) {
		fetches.Add(1)
		<-release
		return []kea.ActiveLease{{IPAddress: "10.0.0.9"}}, nil
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			leases, err := c.get(context.Background(), leaseSrcTTL)
			if err != nil || len(leases) != 1 {
				t.Errorf("concurrent get = %v leases, err %v", len(leases), err)
			}
		}()
	}
	// Let the callers pile onto the in-flight fetch, then release it.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := fetches.Load(); n != 1 {
		t.Fatalf("8 concurrent readers cost %d fetches, want 1", n)
	}
}

// TestLeaseCacheSharesErrors pins that a Kea failure is shared for the window
// (one failure per TTL, not a per-caller retry stampede) and that the next
// stale read retries.
func TestLeaseCacheSharesErrors(t *testing.T) {
	var fetches atomic.Int32
	now := time.Unix(1000, 0)
	boom := errors.New("kea down")
	c := newLeaseCache(func(ctx context.Context) ([]kea.ActiveLease, error) {
		fetches.Add(1)
		return nil, boom
	})
	c.now = func() time.Time { return now }

	for range 3 {
		if _, err := c.get(context.Background(), leaseSrcTTL); !errors.Is(err, boom) {
			t.Fatalf("want the shared fetch error, got %v", err)
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("3 reads during an outage cost %d fetches, want 1", n)
	}
	now = now.Add(leaseSrcTTL + time.Second)
	_, _ = c.get(context.Background(), leaseSrcTTL)
	if n := fetches.Load(); n != 2 {
		t.Fatalf("stale read after an outage cost %d total fetches, want 2 (must retry)", n)
	}
}
