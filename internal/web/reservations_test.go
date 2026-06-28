package web

import (
	"testing"
	"time"

	"ggo-kea-dhcp/internal/web/views"
)

// TestMarkLeaseLastSeen_ShadowSuppressed proves a pinned device's offline "shadow"
// reservation row (same MAC online at a different IP) does NOT inherit the live
// device's last-seen ("just now"), while the online row keeps it and a genuinely
// offline reservation (MAC online nowhere) still ages and flags stale.
func TestMarkLeaseLastSeen_ShadowSuppressed(t *testing.T) {
	s, _ := newTestServer(t)

	const pinnedMAC = "00:1f:80:22:02:f0"
	const goneMAC = "00:1f:80:22:02:aa"
	now := time.Now().Unix()
	s.lastSeen = map[string]int64{
		normalizeMAC(pinnedMAC): now - 5,           // device renewing now -> "just now"
		normalizeMAC(goneMAC):   now - 40*24*60*60, // 40 days ago -> aged + stale
	}

	rows := []views.LeaseRow{
		{IPAddress: "10.0.0.99", HWAddress: pinnedMAC, Presence: "online"},   // the real pinned lease
		{IPAddress: "10.0.0.101", HWAddress: pinnedMAC, Presence: "offline"}, // its shadow reservation
		{IPAddress: "10.0.0.50", HWAddress: goneMAC, Presence: "offline"},    // unrelated offline reservation
	}
	s.markLeaseLastSeen(rows)

	if rows[0].LastSeenText == "" {
		t.Errorf("online pinned row should keep its last-seen, got empty")
	}
	if rows[1].LastSeenText != "" {
		t.Errorf("offline shadow row must not inherit the online device's last-seen, got %q", rows[1].LastSeenText)
	}
	if rows[2].LastSeenText == "" || !rows[2].Stale {
		t.Errorf("unrelated offline reservation should age and flag stale, got text=%q stale=%v", rows[2].LastSeenText, rows[2].Stale)
	}
}
