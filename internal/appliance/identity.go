package appliance

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Leaf helpers shared by the lifecycle engine and the web layer. They live here
// because the engine cannot import web; the web callers reach them through thin
// wrappers so their many call sites stay unchanged.

// portFlexDelim is the byte the Kea flex_id identifier-expression inserts between
// the Option-82 remote-id (relay4[2]) and circuit-id (relay4[1]) sub-options (see
// renderer.go buildHooks). It lets the UI recover the two halves from the opaque
// flex-id; 0x1f (ASCII unit separator) is a control char, so it never collides with
// a printable switch identifier and a flex-id carrying it always renders as hex.
const portFlexDelim = 0x1f

// PortIdent is a decoded switch-port identity: an opaque Key (used to match host
// reservations / labels and posted in forms) plus the remote-id and circuit-id
// halves each rendered two ways - a best-effort ASCII view and the exact colon-hex
// (the /pinning ASCII/hex toggle picks which to show).
type PortIdent struct {
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

// DecodePortIdentity resolves a Kea client-id into a switch-port identity.
//
// Critical: flex_id with replace-client-id (which port pinning uses) reports the
// client-id as a 0x00 byte PREPENDED to the flex-id (per the Kea flex_id docs). The
// host-reservation identifier is the flex-id WITHOUT that leading byte, so we strip
// it here - otherwise the stored reservation is one byte longer than what Kea looks
// up and never matches (the device keeps getting a dynamic lease). ok is false for a
// normal client-id (0x01 + MAC), an empty id, or a 0x00-only id - none are Option-82
// ports and must not be listed as learnable/pinnable (that produced phantom ports).
func DecodePortIdentity(clientID string) (PortIdent, bool) {
	raw := decodeHex(clientID)
	if len(raw) < 2 || raw[0] != 0x00 {
		return PortIdent{}, false
	}
	return PortIdentFromFlex([]byte(raw[1:])), true
}

// PortIdentFromFlex builds a PortIdent from raw flex-id bytes (the form stored in a
// MariaDB host reservation, and the form left after stripping the client-id's 0x00
// prefix). It splits on portFlexDelim into remote-id + circuit-id; the Key is the
// whole flex-id rendered by bytesToPortIdentity so it round-trips through
// flexIDToBytes and matches the reservation Kea looks up.
func PortIdentFromFlex(flex []byte) PortIdent {
	remote, circuit := splitFlexID(flex)
	rid, rhex := renderIDPart(remote)
	cid, chex := renderIDPart(circuit)
	return PortIdent{
		Key:      BytesToPortIdentity(flex),
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
// printable ASCII fails the printable test, so the ASCII view falls back to the hex. The
// only concession is trailing NUL padding - some switches NUL-pad or NUL-terminate
// an otherwise-ASCII identifier ("ether7\x00"), so trailing NULs are trimmed before
// the printable test. Only the ASCII view is affected: the hex view stays exact and
// the opaque Key (the full bytes) is untouched, so reservation matching is unchanged.
func renderIDPart(b []byte) (ascii, hexStr string) {
	if len(b) == 0 {
		return "", ""
	}
	hexStr = colonHex(b)
	if s := string(bytes.TrimRight(b, "\x00")); s != "" && isPrintableASCII(s) {
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

// CapacityOf returns the inclusive address count of a [lo, hi] uint32 range,
// widening to int64 so the +1 can't wrap uint32 on a full-width range.
func CapacityOf(lo, hi uint32) int {
	return int(int64(hi) - int64(lo) + 1)
}

func decodeHex(h string) string {
	h = strings.ReplaceAll(h, ":", "")
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return string(b)
}

// NormalizeMAC lowercases and strips separators so MACs from Kea leases and from
// Netmon frames compare regardless of formatting.
func NormalizeMAC(mac string) string {
	return strings.ToLower(strings.ReplaceAll(mac, ":", ""))
}

// GoSizePresets mirrors the wizard's size buttons server-side (the seed source for
// the Small/Medium/Large tabs); Flat/Custom are handled separately.
var GoSizePresets = map[string]DeviceCounts{
	"small":  {BPX: 15, MCX: 3, Interface: 3, Others: 15, WAA: 2, Nodes: 25},
	"medium": {BPX: 50, MCX: 20, WPX: 2, Interface: 6, Bridge: 2, Stride: 6, Beacon: 2, Others: 18, Nodes: 120},
	"large":  {BPX: 100, MCX: 40, WPX: 16, Interface: 40, Bridge: 10, Stride: 50, Beacon: 50, Others: 20, Nodes: 300},
}

// DefaultSizePreset is the size a brand-new / untouched scope seeds to. It keeps a
// fresh greengo scope from collapsing to a degenerate plan (reserve + catch-alls,
// no device-class pools) when no Counts have been supplied yet.
const DefaultSizePreset = "small"

// SeedDefaultPlan seeds a plan for a scope, substituting the configured default
// size when the scope carries no device counts (a truly fresh scope). A scope that
// already has counts (e.g. a legacy row loaded from pool_spec) seeds from those.
// Non-greengo presets ignore counts, so the substitution is harmless there.
func SeedDefaultPlan(sc ScopeConfig) PoolPlan {
	if sc.Counts == (DeviceCounts{}) {
		sc.Counts = GoSizePresets[DefaultSizePreset]
	}
	return SeedPlan(sc)
}

// UplinkStateKeys / UplinkState are the single definition of the box-level WiFi
// uplink app_state keys: the rollback capture iterates the keys and every writer
// builds its map through UplinkState, so the two cannot drift apart.
var UplinkStateKeys = []string{"uplink_enabled", "uplink_ssid", "uplink_pass"}

// UplinkState renders the box-level uplink settings as their app_state rows.
func UplinkState(enabled bool, ssid, pass string) map[string]string {
	en := "0"
	if enabled {
		en = "1"
	}
	return map[string]string{UplinkStateKeys[0]: en, UplinkStateKeys[1]: ssid, UplinkStateKeys[2]: pass}
}

// isPrintableASCII reports whether every byte of s is in the printable ASCII range
// 0x20..0x7e (space through '~'). A private copy of the web-side predicate: six lines
// beats an import edge for a pure byte test.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// colonHexRe matches a lowercase/uppercase colon-separated hex octet string like
// "00:47:4f" (a single bare octet like "1f" included) - the form
// bytesToPortIdentity renders every key in.
var colonHexRe = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})*$`)

// FlexIDToBytes converts a port-identity key back to the RAW flex-id bytes Kea
// stores in (and matches against) dhcp_identifier. Every key bytesToPortIdentity
// produces is colon-hex, so the hex decode is the whole contract; the ASCII
// fallback only catches a malformed hand-posted value. This is the crux of port
// pinning: Kea matches the reservation against the raw flex-id bytes, so a key
// that decodes to the wrong bytes never matches and the device keeps getting a
// dynamic lease.
func FlexIDToBytes(portIdentity string) []byte {
	if colonHexRe.MatchString(portIdentity) {
		if b, err := hex.DecodeString(strings.ReplaceAll(portIdentity, ":", "")); err == nil {
			return b
		}
	}
	return []byte(portIdentity)
}

// CanonicalPortID re-encodes a legacy port-identity key as colon-hex. Before the key
// became always-hex a printable flex-id was stored as its own text, whose raw bytes
// are that ASCII (the FlexIDToBytes contract above), so re-encoding it on read keeps
// old labels attached to their ports without a migration.
func CanonicalPortID(portID string) string {
	if colonHexRe.MatchString(portID) {
		return portID
	}
	return colonHex([]byte(portID))
}
