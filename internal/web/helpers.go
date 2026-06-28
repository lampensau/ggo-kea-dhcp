package web

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
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

// portFlexDelim is the byte the Kea flex_id identifier-expression inserts between
// the Option-82 remote-id (relay4[2]) and circuit-id (relay4[1]) sub-options (see
// renderer.go buildHooks). It lets the UI recover the two halves from the opaque
// flex-id; 0x1f (ASCII unit separator) is a control char, so it never collides with
// a printable switch identifier and a flex-id carrying it always renders as hex.
const portFlexDelim = 0x1f

// portStaleAfter is how long a pinned-but-offline port may go unseen before it is
// flagged stale in the UI (a hint to unpin a long-gone device), in seconds.
const portStaleAfter = 14 * 24 * 60 * 60 // 14 days

// portIdent is a decoded switch-port identity: an opaque Key (used to match host
// reservations / labels and posted in forms) plus the remote-id and circuit-id
// halves each rendered two ways - a best-effort ASCII view and the exact colon-hex
// (the /pinning ASCII/hex toggle picks which to show).
type portIdent struct {
	Key        string
	RemoteID   string
	RemoteHex  string
	CircuitID  string
	CircuitHex string
	// Delimited is true when the flex-id carries the portFlexDelim separator, i.e. it
	// was produced by the current (post-upgrade) identifier-expression. A non-delimited
	// flex-id is a pre-upgrade leftover that can never match a new reservation, so the
	// UI prefers a delimited entry over a non-delimited one for the same device.
	Delimited bool
}

// decodePortIdentity resolves a Kea client-id into a switch-port identity.
//
// Critical: flex_id with replace-client-id (which port pinning uses) reports the
// client-id as a 0x00 byte PREPENDED to the flex-id (per the Kea flex_id docs). The
// host-reservation identifier is the flex-id WITHOUT that leading byte, so we strip
// it here - otherwise the stored reservation is one byte longer than what Kea looks
// up and never matches (the device keeps getting a dynamic lease). ok is false for a
// normal client-id (0x01 + MAC), an empty id, or a 0x00-only id - none are Option-82
// ports and must not be listed as learnable/pinnable (that produced phantom ports).
func decodePortIdentity(clientID string) (portIdent, bool) {
	raw := decodeHex(clientID)
	if len(raw) < 2 || raw[0] != 0x00 {
		return portIdent{}, false
	}
	return portIdentFromFlex([]byte(raw[1:])), true
}

// portIdentFromFlex builds a portIdent from raw flex-id bytes (the form stored in a
// MariaDB host reservation, and the form left after stripping the client-id's 0x00
// prefix). It splits on portFlexDelim into remote-id + circuit-id; the Key is the
// whole flex-id rendered by bytesToPortIdentity so it round-trips through
// flexIDToBytes and matches the reservation Kea looks up.
func portIdentFromFlex(flex []byte) portIdent {
	remote, circuit := splitFlexID(flex)
	rid, rhex := renderIDPart(remote)
	cid, chex := renderIDPart(circuit)
	return portIdent{
		Key:      bytesToPortIdentity(flex),
		RemoteID: rid, RemoteHex: rhex,
		CircuitID: cid, CircuitHex: chex,
		Delimited: bytes.IndexByte(flex, portFlexDelim) >= 0,
	}
}

// splitFlexID separates a flex-id into its remote-id and circuit-id halves at the
// first portFlexDelim. A flex-id without the delimiter (a pre-upgrade pin, or a
// relay that inserts only one sub-option) is treated as a lone remote-id.
func splitFlexID(flex []byte) (remote, circuit []byte) {
	if i := bytes.IndexByte(flex, portFlexDelim); i >= 0 {
		return flex[:i], flex[i+1:]
	}
	return flex, nil
}

// renderIDPart renders one Option-82 sub-option for the UI: a best-effort ASCII view
// (the printable text, else the hex) and the exact lowercase colon-hex. An empty
// sub-option yields two empty strings (shown as an em dash).
//
// Binary sub-options are detected and shown as hex automatically: any byte outside
// printable ASCII fails isPrintable, so the ASCII view falls back to the hex. The
// only concession is trailing NUL padding - some switches NUL-pad or NUL-terminate
// an otherwise-ASCII identifier ("ether7\x00"), so trailing NULs are trimmed before
// the printable test. Only the ASCII view is affected: the hex view stays exact and
// the opaque Key (the full bytes) is untouched, so reservation matching is unchanged.
func renderIDPart(b []byte) (ascii, hexStr string) {
	if len(b) == 0 {
		return "", ""
	}
	hexStr = colonHex(b)
	if s := string(bytes.TrimRight(b, "\x00")); isPrintable(s) {
		return s, hexStr
	}
	return hexStr, hexStr
}

// colonHex renders bytes as lowercase colon-separated hex ("00:47:4f").
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

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

// capacityOf returns the inclusive address count of a [lo, hi] uint32 range,
// widening to int64 so the +1 can't wrap uint32 on a full-width range.
func capacityOf(lo, hi uint32) int {
	return int(int64(hi) - int64(lo) + 1)
}

func parseRangeCapacity(rangeStr string) int {
	lo, hi, ok := kea.ParsePoolRange(rangeStr)
	if !ok {
		return 0
	}
	return capacityOf(lo, hi)
}

func decodeHex(h string) string {
	h = strings.ReplaceAll(h, ":", "")
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return string(b)
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return len(s) > 0
}
