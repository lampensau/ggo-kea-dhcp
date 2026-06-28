package web

import (
	"net"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/kea"
)

// TestBuildImportReservations checks the CSV row-decision core: a good row imports,
// a bad MAC and an out-of-subnet IP are skipped with reasons, an intra-file duplicate
// IP is dropped, and a blank hostname is filled from the (stubbed) scan inventory.
func TestBuildImportReservations(t *testing.T) {
	// subnetFor: accept only 10.0.0.0/24 (subnet id 1).
	subnetFor := func(ip net.IP) (int, bool) {
		_, n, _ := net.ParseCIDR("10.0.0.0/24")
		if n.Contains(ip) {
			return 1, true
		}
		return 0, false
	}
	noConflict := func(int, uint32, string, []byte, string) (string, bool) { return "", false }
	hostnameFor := func(mac string) string {
		if mac == "00:1f:80:00:00:01" {
			return "beltpack-1"
		}
		return ""
	}

	records := [][]string{
		{"mac", "ip", "hostname"},                  // header - skipped
		{"00:1f:80:00:00:01", "10.0.0.10", ""},     // good, blank hostname -> scan fill
		{"00:1f:80:00:00:02", "10.0.0.11", "desk"}, // good, explicit hostname
		{"not-a-mac", "10.0.0.12", ""},             // bad MAC - skip
		{"00:1f:80:00:00:03", "10.9.9.9", ""},      // out of subnet - skip
		{"00:1f:80:00:00:04", "10.0.0.10", ""},     // duplicate IP - skip
		{"", "", ""},                               // blank line - ignored
	}

	toInsert, owners, skipped, problems := buildImportReservations(records, subnetFor, noConflict, hostnameFor)

	if len(toInsert) != 2 {
		t.Fatalf("want 2 imported, got %d (%+v)", len(toInsert), toInsert)
	}
	if len(owners) != 2 {
		t.Errorf("want 2 owners, got %d", len(owners))
	}
	if skipped != 3 {
		t.Errorf("want 3 skipped (bad MAC, out-of-subnet, dup IP), got %d (%v)", skipped, problems)
	}
	if toInsert[0].Hostname != "beltpack-1" {
		t.Errorf("blank hostname should be filled from scan: got %q", toInsert[0].Hostname)
	}
	if toInsert[1].Hostname != "desk" {
		t.Errorf("explicit hostname should be kept: got %q", toInsert[1].Hostname)
	}
	if toInsert[0].IPv4Address != kea.IPToUint32(net.ParseIP("10.0.0.10")) {
		t.Errorf("unexpected IP encoding for first row")
	}
}

// TestBuildImportReservations_DBConflict covers the conflictFn branch the other tests
// stub out: a row that passes MAC/IP/subnet validation but collides with an existing DB
// reservation must be skipped with the conflict reason propagated verbatim, while a
// non-conflicting row in the same file still imports.
func TestBuildImportReservations_DBConflict(t *testing.T) {
	subnetFor := func(net.IP) (int, bool) { return 1, true }
	// Conflict only for 10.0.0.11; the reason string must surface in problems.
	conflictFn := func(_ int, _ uint32, ipStr string, _ []byte, _ string) (string, bool) {
		if ipStr == "10.0.0.11" {
			return "10.0.0.11 already reserved for aa:bb:cc:dd:ee:ff", true
		}
		return "", false
	}
	records := [][]string{
		{"00:1f:80:00:00:01", "10.0.0.10", ""}, // no conflict -> imported
		{"00:1f:80:00:00:02", "10.0.0.11", ""}, // DB conflict -> skipped
	}
	toInsert, _, skipped, problems := buildImportReservations(records, subnetFor, conflictFn, func(string) string { return "" })

	if len(toInsert) != 1 || skipped != 1 {
		t.Fatalf("want 1 imported / 1 skipped, got %d / %d (%v)", len(toInsert), skipped, problems)
	}
	if toInsert[0].IPv4Address != kea.IPToUint32(net.ParseIP("10.0.0.10")) {
		t.Errorf("non-conflicting row mapped to wrong IP")
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "already reserved") {
		t.Errorf("conflict reason should propagate, got %v", problems)
	}
}

// TestBuildImportReservations_TooFewColumns checks a one-column row (no IP) is skipped
// with a clear reason rather than panicking on rec[1].
func TestBuildImportReservations_TooFewColumns(t *testing.T) {
	subnetFor := func(net.IP) (int, bool) { return 1, true }
	noConflict := func(int, uint32, string, []byte, string) (string, bool) { return "", false }
	records := [][]string{{"00:1f:80:00:00:01"}} // mac only, no ip
	toInsert, _, skipped, problems := buildImportReservations(records, subnetFor, noConflict, func(string) string { return "" })
	if len(toInsert) != 0 || skipped != 1 {
		t.Fatalf("want 0 imported / 1 skipped, got %d / %d", len(toInsert), skipped)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "at least mac,ip") {
		t.Errorf("want a too-few-columns reason, got %v", problems)
	}
}

// TestBuildImportReservations_HeaderAfterBlankLine verifies a "mac" header is skipped
// even when a blank leading line pushes it off row 0 (so it isn't mis-flagged as an
// invalid-MAC data row).
func TestBuildImportReservations_HeaderAfterBlankLine(t *testing.T) {
	subnetFor := func(net.IP) (int, bool) { return 1, true }
	noConflict := func(int, uint32, string, []byte, string) (string, bool) { return "", false }
	records := [][]string{
		{""},                                   // blank leading line
		{"mac", "ip", "hostname"},              // header now at index 1
		{"00:1f:80:00:00:01", "10.0.0.10", ""}, // one good row
	}
	toInsert, _, skipped, problems := buildImportReservations(records, subnetFor, noConflict, func(string) string { return "" })
	if len(toInsert) != 1 || skipped != 0 {
		t.Fatalf("want 1 imported / 0 skipped, got %d / %d (%v)", len(toInsert), skipped, problems)
	}
}

// TestBuildImportReservations_BOMAndDupMAC covers the two import-hardening branches
// added with the bulk importer: a UTF-8 BOM on the first field (Excel/Sheets prepend
// one) must not break the first MAC parse, and a MAC repeated within the file is
// skipped (a plain ON DUPLICATE KEY insert would otherwise silently collapse the two).
func TestBuildImportReservations_BOMAndDupMAC(t *testing.T) {
	subnetFor := func(net.IP) (int, bool) { return 1, true }
	noConflict := func(int, uint32, string, []byte, string) (string, bool) { return "", false }
	hostnameFor := func(string) string { return "" }

	records := [][]string{
		{"\ufeff00:1f:80:00:00:01", "10.0.0.10", ""}, // BOM-prefixed first MAC -> must still parse
		{"00:1f:80:00:00:01", "10.0.0.11", ""},       // same MAC again -> skipped as a file dup
		{"00:1f:80:00:00:02", "10.0.0.12", ""},       // distinct MAC -> kept
	}
	toInsert, _, skipped, problems := buildImportReservations(records, subnetFor, noConflict, hostnameFor)

	if len(toInsert) != 2 {
		t.Fatalf("want 2 imported (BOM row + distinct), got %d (%+v)", len(toInsert), toInsert)
	}
	// The BOM row must have parsed into a clean 6-byte MAC (no BOM bytes in the identifier).
	if got := len(toInsert[0].Identifier); got != 6 {
		t.Errorf("BOM-prefixed MAC identifier len = %d, want 6 (BOM not stripped?)", got)
	}
	if toInsert[0].IPv4Address != kea.IPToUint32(net.ParseIP("10.0.0.10")) {
		t.Errorf("BOM row mapped to the wrong IP: %d", toInsert[0].IPv4Address)
	}
	if skipped != 1 {
		t.Errorf("want 1 skipped (the duplicate MAC), got %d (%v)", skipped, problems)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "duplicated in file") {
		t.Errorf("want a 'duplicated in file' problem, got %v", problems)
	}
}
