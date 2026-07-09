package web

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// classifyMAC delegates to the shared kea classification table so dashboard and
// lease labels never disagree with the Kea client-classes that actually matched.
func classifyMAC(mac string) string {
	return kea.ClassifyMAC(mac)
}

// buildLeaseRows converts Kea active leases into the display rows used by the
// leases page (first paint and the Datastar search fragment), sorted by IP so the
// table scans top-to-bottom in address order.
func buildLeaseRows(leases []kea.ActiveLease) []views.LeaseRow {
	now := time.Now().Unix()
	rows := make([]views.LeaseRow, 0, len(leases))
	for _, l := range leases {
		rows = append(rows, views.LeaseRow{
			IPAddress: l.IPAddress,
			HWAddress: l.HWAddress,
			ClientID:  l.ClientID,
			Hostname:  l.Hostname,
			Class:     classifyMAC(l.HWAddress),
			SubnetID:  l.SubnetID,
			ExpiresIn: leaseExpiryFrom(l.Cltt, l.ValidLft, now),
			ExpiresAt: leaseExpiryAt(l.Cltt, l.ValidLft),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return leaseIPKey(rows[i].IPAddress) < leaseIPKey(rows[j].IPAddress)
	})
	return rows
}

// isLeaseActive reports whether a Kea lease is currently held by a client: in the
// default/assigned state (0 - not declined=1 / expired-reclaimed=2 / released=3)
// and not past its valid lifetime. Kea returns expired-but-not-yet-reclaimed
// leases from lease4-get-page (they linger in the DB until the reclamation cycle
// runs), so a state-0 lease can still be time-expired - both checks are needed.
func isLeaseActive(l kea.ActiveLease, now int64) bool {
	if l.State != 0 {
		return false
	}
	if l.ValidLft >= 0xffffffff {
		return true // infinite lease - never expires
	}
	if l.Cltt <= 0 || l.ValidLft <= 0 {
		return true // no timing info - don't hide an otherwise-assigned lease
	}
	return l.Cltt+l.ValidLft > now
}

// activeLeases returns only the currently-held leases (see isLeaseActive). The
// dashboard's "Active leases" summary uses it so a lapsed-but-not-yet-reclaimed
// lease is not shown as active; the full /leases page still lists everything.
func activeLeases(leases []kea.ActiveLease) []kea.ActiveLease {
	now := time.Now().Unix()
	out := make([]kea.ActiveLease, 0, len(leases))
	for _, l := range leases {
		if isLeaseActive(l, now) {
			out = append(out, l)
		}
	}
	return out
}

// leaseIPKey is an IPv4 sort key; an unparseable address sorts last.
func leaseIPKey(s string) uint32 {
	if ip := net.ParseIP(s).To4(); ip != nil {
		return kea.IPToUint32(ip)
	}
	return ^uint32(0)
}

// leaseExpiryFrom renders a lease's remaining time from the two fields Kea
// actually returns: cltt (client last transaction time, epoch) and valid-lft (the
// lifetime in seconds). Kea does NOT send an absolute "expire" field, so the
// expiry is cltt + valid-lft. Missing timing (cltt/valid-lft <= 0) renders as an
// em dash; Kea's infinite-lifetime sentinel (0xffffffff) renders "never".
func leaseExpiryFrom(cltt, validLft, now int64) string {
	if cltt <= 0 || validLft <= 0 {
		return "—"
	}
	if validLft >= 0xffffffff {
		return "never"
	}
	return leaseExpiry(cltt+validLft, now)
}

// leaseExpiryAt returns the absolute lease-expiry epoch (cltt+valid-lft) for the
// client-side countdown: 0 when timing is unknown (rendered as an em dash), -1 for
// Kea's infinite-lifetime sentinel ("never"). Absolute, so a cached fragment never
// shows a frozen value - the browser recomputes the remaining time each second.
func leaseExpiryAt(cltt, validLft int64) int64 {
	switch {
	case cltt <= 0 || validLft <= 0:
		return 0
	case validLft >= 0xffffffff:
		return -1
	default:
		return cltt + validLft
	}
}

// leaseExpiry renders the time remaining until an absolute expiry epoch. A
// non-positive expire renders as an em dash rather than a misleading countdown.
func leaseExpiry(expire, now int64) string {
	if expire <= 0 {
		return "—"
	}
	rem := expire - now
	switch {
	case rem <= 0:
		return "expired"
	case rem < 60:
		return fmt.Sprintf("%ds", rem) // sub-minute: show seconds, not a misleading "0m"
	case rem < 3600:
		return fmt.Sprintf("%dm", rem/60)
	default:
		h, m := rem/3600, (rem%3600)/60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	}
}

// portStaleAfter is how long a pinned-but-offline port may go unseen before it is
// flagged stale in the UI (a hint to unpin a long-gone device), in seconds.
const portStaleAfter = 14 * 24 * 60 * 60 // 14 days

// relativeAgo renders how long ago an epoch-seconds timestamp was, in coarse buckets
// (just now / Nm / Nh / Nd ago). Coarse on purpose: the live SSE channel hashes each
// fragment and re-broadcasts on change, so a second-precision value would thrash it.
// An absent/zero timestamp renders empty.
func relativeAgo(then, now int64) string {
	if then <= 0 {
		return ""
	}
	d := now - then
	switch {
	case d < 60:
		return "just now"
	case d < 3600:
		return fmt.Sprintf("%dm ago", d/60)
	case d < 86400:
		return fmt.Sprintf("%dh ago", d/3600)
	default:
		return fmt.Sprintf("%dd ago", d/86400)
	}
}

// liveMAC returns the normalized MAC for a row backed by a real live lease, or ""
// for the pinned-but-offline placeholder ("-") or an empty value - so the same-MAC
// dedup only considers devices actually seen on the wire.
func liveMAC(hw string) string {
	if hw == "" || hw == "-" {
		return ""
	}
	return normalizeMAC(hw)
}

func parseRangeCapacity(rangeStr string) int {
	lo, hi, ok := kea.ParsePoolRange(rangeStr)
	if !ok {
		return 0
	}
	return capacityOf(lo, hi)
}

// opCtx bounds one background IO operation (live ticker, samplers, memoized
// lease fetches, event-driven publishes) that no HTTP request scopes. 15s
// comfortably covers the Kea client's 10s transport timeout plus MariaDB
// round-trips; requests use r.Context() instead.
func opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}
