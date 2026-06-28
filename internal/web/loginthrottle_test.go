package web

import (
	"testing"
	"time"
)

func TestBackoffFor(t *testing.T) {
	cases := []struct {
		fails int
		want  time.Duration
	}{
		{1, 0},
		{3, 0}, // within freebies
		{4, 1 * time.Second},
		{5, 2 * time.Second},
		{6, 4 * time.Second},
		{100, loginBackoffCap}, // capped, no overflow
	}
	for _, c := range cases {
		if got := backoffFor(c.fails); got != c.want {
			t.Errorf("backoffFor(%d) = %s, want %s", c.fails, got, c.want)
		}
	}
}

func TestLoginThrottle(t *testing.T) {
	tr := newLoginThrottle()
	now := time.Unix(1_700_000_000, 0)
	tr.now = func() time.Time { return now }

	// Fresh IP is allowed.
	if ok, _ := tr.allow("1.2.3.4"); !ok {
		t.Fatal("fresh IP should be allowed")
	}

	// Within freebies: failures impose no delay.
	for range loginFreebies {
		tr.fail("1.2.3.4")
	}
	if ok, _ := tr.allow("1.2.3.4"); !ok {
		t.Fatal("within freebies should still be allowed")
	}

	// One more failure → backoff engages; an immediate retry is blocked.
	tr.fail("1.2.3.4")
	if ok, retry := tr.allow("1.2.3.4"); ok || retry <= 0 {
		t.Fatalf("after backoff, allow should block with positive retry, got ok=%v retry=%s", ok, retry)
	}

	// After the window elapses, the IP is allowed again.
	now = now.Add(2 * time.Second)
	if ok, _ := tr.allow("1.2.3.4"); !ok {
		t.Fatal("after the backoff window the IP should be allowed")
	}

	// A success clears the IP entirely.
	tr.fail("1.2.3.4")
	tr.succeed("1.2.3.4")
	if ok, _ := tr.allow("1.2.3.4"); !ok {
		t.Fatal("succeed should clear the IP's backoff")
	}

	// A different IP is independent.
	if ok, _ := tr.allow("9.9.9.9"); !ok {
		t.Fatal("unrelated IP should be unaffected")
	}
}

func TestLoginThrottlePrune(t *testing.T) {
	tr := newLoginThrottle()
	now := time.Unix(1_700_000_000, 0)
	tr.now = func() time.Time { return now }

	tr.fail("1.2.3.4")
	// Advance past the TTL and trigger a prune via a fail on another IP.
	now = now.Add(loginEntryTTL + time.Minute)
	tr.fail("5.6.7.8")
	tr.mu.Lock()
	_, stale := tr.entries["1.2.3.4"]
	tr.mu.Unlock()
	if stale {
		t.Fatal("stale entry should have been pruned")
	}
}
