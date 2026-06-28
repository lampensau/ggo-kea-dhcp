package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"ggo-kea-dhcp/internal/web/views"
)

// TestMemoizeLeaseIPs verifies the shared lease-IP closure collapses same-cycle calls
// into one fetch, refreshes after the TTL, and keeps the last-known set on a failed
// fetch (so a transient Kea error does not blank every presence dot).
func TestMemoizeLeaseIPs(t *testing.T) {
	calls := 0
	results := [][]string{{"10.0.0.20"}, {"10.0.0.20", "10.0.0.21"}}
	ok := true
	now := time.Unix(1000, 0)
	fetch := func() ([]string, bool) {
		if !ok {
			calls++
			return nil, false
		}
		r := results[min(calls, len(results)-1)]
		calls++
		return r, true
	}
	get := memoizeLeaseIPs(fetch, 8*time.Second, func() time.Time { return now })

	// Three calls within the TTL: one underlying fetch, identical result.
	first := get()
	get()
	if got := get(); calls != 1 || len(got) != 1 || len(first) != 1 {
		t.Fatalf("within TTL: calls=%d (want 1), result=%v", calls, got)
	}
	// Past the TTL: a fresh fetch, new result.
	now = now.Add(9 * time.Second)
	if got := get(); calls != 2 || len(got) != 2 {
		t.Fatalf("after TTL: calls=%d (want 2), result=%v", calls, got)
	}
	// A failed fetch past the TTL keeps the last-known set (no blanked dots).
	now = now.Add(9 * time.Second)
	ok = false
	if got := get(); len(got) != 2 {
		t.Fatalf("on fetch failure expected last-known 2 IPs, got %v", got)
	}
}

// TestMemoizeLeaseIPs_StaleWhileRevalidate verifies a concurrent caller returns the
// stale cached set immediately while one refresh is in flight (the fetch runs without
// the lock held), and the refreshing caller gets the fresh result.
func TestMemoizeLeaseIPs_StaleWhileRevalidate(t *testing.T) {
	now := time.Unix(1000, 0)
	started := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	fetch := func() ([]string, bool) {
		calls++
		if calls == 1 {
			return []string{"10.0.0.5"}, true // prime synchronously
		}
		close(started) // second fetch: signal entry, then block
		<-release
		return []string{"10.0.0.6"}, true
	}
	get := memoizeLeaseIPs(fetch, time.Second, func() time.Time { return now })

	if got := get(); len(got) != 1 {
		t.Fatalf("prime: got %v", got)
	}
	now = now.Add(2 * time.Second) // expire TTL (before launching the goroutine: no race on now)

	done := make(chan []string, 1)
	go func() { done <- get() }() // wins the single-flight, blocks inside fetch
	<-started

	// Concurrent caller: must get the stale value without blocking on the in-flight fetch.
	if got := get(); len(got) != 1 || got[0] != "10.0.0.5" {
		t.Fatalf("concurrent caller got %v, want stale [10.0.0.5]", got)
	}
	close(release)
	if r := <-done; len(r) != 1 || r[0] != "10.0.0.6" {
		t.Fatalf("refresher got %v, want fresh [10.0.0.6]", r)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (prime + one refresh, no double fetch)", calls)
	}
}

// TestNetHealthView_RendersSignals asserts the card maps backend severities to
// the right status-dot variants and surfaces detail fields, and that the empty
// view renders the idle placeholder.
func TestNetHealthView_RendersSignals(t *testing.T) {
	v := views.NetHealthView{Interfaces: []views.NetHealthIface{{
		Iface:     "eth0",
		Available: true,
		Level:     "full",
		Rows: []views.NetHealthRow{
			{Kind: "igmp", Severity: "ok", Title: "IGMP querier present", Detail: "querier 10.0.0.1 v2"},
			{Kind: "rogue_dhcp", Severity: "error", Title: "Rogue DHCP server 10.0.0.250", Detail: "server 10.0.0.250 · de:ad:be:ef:00:01"},
		},
	}}}

	var b strings.Builder
	if err := views.NetHealth(v).Render(context.Background(), &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	html := b.String()
	for _, want := range []string{
		`id="net-health"`,
		"status-dot ok",  // ok severity → ok dot
		"status-dot err", // error severity → err dot
		"IGMP querier present",
		"de:ad:be:ef:00:01",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered card missing %q\n%s", want, html)
		}
	}

	// Empty view → idle placeholder, no detector rows.
	var eb strings.Builder
	_ = views.NetHealth(views.NetHealthView{}).Render(context.Background(), &eb)
	if !strings.Contains(eb.String(), "Monitoring idle") {
		t.Errorf("empty card missing idle placeholder:\n%s", eb.String())
	}
}

// TestNetHealthChangeOnlyPush asserts publishIfChanged suppresses an unchanged
// net-health fragment (the live ticker stays quiet on a stable network).
func TestNetHealthChangeOnlyPush(t *testing.T) {
	h := newLiveHub()
	v := views.NetHealthView{Interfaces: []views.NetHealthIface{{Iface: "eth0", Available: true, Level: "full"}}}
	frag := renderFragment(views.NetHealth(v))

	if !h.publishIfChanged("net-health", frag) {
		t.Fatal("first publish should broadcast")
	}
	if h.publishIfChanged("net-health", frag) {
		t.Fatal("identical fragment should be suppressed (change-only push)")
	}
}
