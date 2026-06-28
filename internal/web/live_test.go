package web

import (
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

// TestLeasesSignatureChangeOnly proves the ticker's gate: an identical lease set
// (in any order) hashes the same, so markChanged suppresses a re-render; a changed
// set hashes differently and forces one. Lease expiry is excluded - a renewal
// alone must not re-render dash-tiles/pool-table (neither shows expiry).
func TestLeasesSignatureChangeOnly(t *testing.T) {
	a := []kea.ActiveLease{{IPAddress: "10.0.0.5", HWAddress: "aa"}, {IPAddress: "10.0.0.6", HWAddress: "bb"}}
	reordered := []kea.ActiveLease{{IPAddress: "10.0.0.6", HWAddress: "bb"}, {IPAddress: "10.0.0.5", HWAddress: "aa"}}
	if leasesSignature(a) != leasesSignature(reordered) {
		t.Fatal("signature must be order-independent")
	}
	if leasesSignature(a) == leasesSignature(a[:1]) {
		t.Fatal("dropping a lease must change the signature")
	}

	h := newLiveHub()
	if !h.markChanged("ticker-leases", leasesSignature(a)) {
		t.Fatal("first signature should report changed")
	}
	if h.markChanged("ticker-leases", leasesSignature(reordered)) {
		t.Fatal("identical (reordered) lease set should NOT report changed → render skipped")
	}
	if !h.markChanged("ticker-leases", leasesSignature(a[:1])) {
		t.Fatal("changed lease set should report changed → render runs")
	}
}

// TestLeasesSignatureIncludesClientID proves a lease gaining/changing its Option-82
// flex-id (client-id) on a STABLE IP+MAC moves the signature, so the /pinning learnable
// list re-renders live instead of only on a full reload (issue #6, confirmed on the Pi:
// 10.0.0.187 / c8:ff:bf:0e:6f:e6 carrying both a normal client-id and an Option-82 one).
func TestLeasesSignatureIncludesClientID(t *testing.T) {
	normal := []kea.ActiveLease{{IPAddress: "10.0.0.187", HWAddress: "c8:ff:bf:0e:6f:e6", ClientID: "01:c8:ff:bf:0e:6f:e6"}}
	option82 := []kea.ActiveLease{{IPAddress: "10.0.0.187", HWAddress: "c8:ff:bf:0e:6f:e6", ClientID: "00:41:56:2d:45:64:67:65:2d:33:1f:65:74:68:65:72:35"}}
	if leasesSignature(normal) == leasesSignature(option82) {
		t.Fatal("a client-id change on the same IP+MAC must change the signature (learnable port hot-load)")
	}
}

// TestPresenceSignatureTriggersRefresh proves a device crossing the online/offline
// boundary changes the combined lease+presence signature (so the leases-body rows
// re-broadcast) even though the lease set is unchanged, while an unrelated host's
// liveness and result ordering do not churn it.
func TestPresenceSignatureTriggersRefresh(t *testing.T) {
	leases := []kea.ActiveLease{{IPAddress: "10.0.0.5", HWAddress: "00:1f:80:20:00:01"}, {IPAddress: "10.0.0.6", HWAddress: "00:1f:80:20:00:02"}}
	none := map[string]bool{}
	one := map[string]bool{"10.0.0.5": true}                    // first lease IP reachable
	both := map[string]bool{"10.0.0.5": true, "10.0.0.6": true} // both reachable

	sig := func(reachable map[string]bool) uint64 {
		return leasesSignature(leases) ^ presenceSignature(leases, reachable)
	}

	if sig(none) == sig(one) {
		t.Fatal("a leased device coming online must change the combined signature")
	}
	if sig(one) == sig(both) {
		t.Fatal("a second leased device coming online must change the signature")
	}
	// An unrelated (non-leased) IP's reachability must NOT change it.
	withStranger := map[string]bool{"10.0.0.5": true, "10.0.0.99": true}
	if sig(one) != sig(withStranger) {
		t.Fatal("a non-leased IP's presence must not churn the lease signature")
	}
	// Presence is order-independent like the lease hash.
	reordered := []kea.ActiveLease{leases[1], leases[0]}
	if (leasesSignature(reordered) ^ presenceSignature(reordered, both)) != sig(both) {
		t.Fatal("combined signature must be order-independent")
	}
}

// recvOne returns the next fragment on ch, or ok=false if none is buffered.
func recvOne(ch chan string) (string, bool) {
	select {
	case f, open := <-ch:
		return f, open
	default:
		return "", false
	}
}

func TestLiveHubPublishReachesSubscriber(t *testing.T) {
	h := newLiveHub()
	ch := h.subscribe("")
	if got := h.clientCount(); got != 1 {
		t.Fatalf("clientCount = %d, want 1", got)
	}

	h.publish(`<span id="state-badge">ACTIVE</span>`)
	got, ok := recvOne(ch)
	if !ok {
		t.Fatal("subscriber received no fragment")
	}
	if got != `<span id="state-badge">ACTIVE</span>` {
		t.Fatalf("fragment = %q", got)
	}
}

func TestLiveHubChangeOnlyPush(t *testing.T) {
	h := newLiveHub()
	ch := h.subscribe("")

	// First publish for a region always broadcasts.
	if !h.publishIfChanged("state-badge", `<span id="state-badge">ACTIVE</span>`) {
		t.Fatal("first publishIfChanged should broadcast")
	}
	// Identical payload for the same region is suppressed.
	if h.publishIfChanged("state-badge", `<span id="state-badge">ACTIVE</span>`) {
		t.Fatal("unchanged publishIfChanged should be suppressed")
	}
	// A changed payload broadcasts again.
	if !h.publishIfChanged("state-badge", `<span id="state-badge">CONFIGURING</span>`) {
		t.Fatal("changed publishIfChanged should broadcast")
	}

	// Exactly two fragments should have reached the subscriber.
	if _, ok := recvOne(ch); !ok {
		t.Fatal("missing first fragment")
	}
	if _, ok := recvOne(ch); !ok {
		t.Fatal("missing changed fragment")
	}
	if extra, ok := recvOne(ch); ok {
		t.Fatalf("unexpected extra fragment %q (change-only push failed)", extra)
	}
}

// TestLiveHubRebroadcastLastBypassesGate proves rebroadcastLast re-sends a region's last
// fragment even when the change-only gate would suppress it - the recovery path for a
// client whose presence dots froze because it missed an earlier push and the global state
// then went stable. It re-sends the cached fragment without the caller re-rendering.
func TestLiveHubRebroadcastLastBypassesGate(t *testing.T) {
	h := newLiveHub()
	ch := h.subscribe("") // empty page receives all regions
	frag := `<tbody id="leases-body">A</tbody>`

	// Before any broadcast, rebroadcastLast is a no-op (nothing cached yet).
	h.rebroadcastLast("leases-body")
	if _, ok := recvOne(ch); ok {
		t.Fatal("rebroadcastLast must send nothing before the region has ever broadcast")
	}

	if !h.publishIfChanged("leases-body", frag) {
		t.Fatal("first publish should broadcast")
	}
	if _, ok := recvOne(ch); !ok {
		t.Fatal("missing first fragment")
	}
	// An identical change-only publish is suppressed (the gate that strands clients).
	if h.publishIfChanged("leases-body", frag) {
		t.Fatal("identical publishIfChanged should be suppressed")
	}
	// rebroadcastLast re-sends the cached fragment regardless, reconciling a stale client.
	h.rebroadcastLast("leases-body")
	got, ok := recvOne(ch)
	if !ok {
		t.Fatal("rebroadcastLast must deliver even an unchanged fragment")
	}
	if got != frag {
		t.Fatalf("rebroadcastLast delivered %q, want the cached %q", got, frag)
	}
}

func TestLiveHubPerRegionHashing(t *testing.T) {
	h := newLiveHub()
	h.subscribe("")

	// Distinct regions are tracked independently: identical text under two
	// different region keys both broadcast (they are different DOM targets).
	if !h.publishIfChanged("leases-body", `<tbody id="leases-body"></tbody>`) {
		t.Fatal("first leases publish should broadcast")
	}
	if !h.publishIfChanged("learnable-body", `<tbody id="learnable-body"></tbody>`) {
		t.Fatal("first learnable publish should broadcast (independent region)")
	}
}

func TestLiveHubUnsubscribe(t *testing.T) {
	h := newLiveHub()
	ch := h.subscribe("")
	h.unsubscribe(ch)
	if got := h.clientCount(); got != 0 {
		t.Fatalf("clientCount after unsubscribe = %d, want 0", got)
	}
	if _, open := <-ch; open {
		t.Fatal("channel should be closed after unsubscribe")
	}
	// Publishing with no subscribers must not panic.
	h.publish("noop")
	if h.publishIfChanged("r", "x") != true {
		t.Fatal("publishIfChanged should still report change with zero subscribers")
	}
}
