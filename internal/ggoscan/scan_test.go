package ggoscan

import (
	"bytes"
	"net"
	"os"
	"regexp"
	"testing"
)

// reply0x11 builds a G-G device-info reply: header + body with name@0, MAC@0x12,
// firmware@0x2e.
func reply0x11(name string, mac [6]byte, fw string) []byte {
	body := make([]byte, 0x2e+0x40)
	copy(body, name) // NUL-padded by the zeroed buffer
	copy(body[0x12:], mac[:])
	copy(body[0x2e:], fw)
	return append([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, body...)
}

func TestParseScanReply(t *testing.T) {
	mac := [6]byte{0x00, 0x1f, 0x80, 0x22, 0x51, 0x30}
	dev, ok := parseScanReply(reply0x11("TestingMCXD", mac, "MCXi 5.0.7.9165"), "10.0.0.50")
	if !ok {
		t.Fatal("parse failed on a valid 0x11 reply")
	}
	if dev.Name != "TestingMCXD" {
		t.Errorf("name = %q, want TestingMCXD", dev.Name)
	}
	if dev.MAC != "00:1f:80:22:51:30" {
		t.Errorf("mac = %q, want 00:1f:80:22:51:30", dev.MAC)
	}
	if dev.IP != "10.0.0.50" {
		t.Errorf("ip = %q, want 10.0.0.50", dev.IP)
	}
	if dev.Model != "MCXi" || dev.Version != "5.0.7.9165" {
		t.Errorf("model/version = %q/%q, want MCXi/5.0.7.9165", dev.Model, dev.Version)
	}

	// A non-0x11 frame (e.g. the 0x10 request echoed) and a too-short frame are rejected.
	if _, ok := parseScanReply([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x10, 0x00, 0x00}, "x"); ok {
		t.Error("parsed a 0x10 request as a reply")
	}
	if _, ok := parseScanReply([]byte{0x47, 0x2d, 0x47, 0x00}, "x"); ok {
		t.Error("parsed a truncated frame")
	}
}

func TestReleaseMismatchWithinFamily(t *testing.T) {
	mac := func(n byte) [6]byte { return [6]byte{0, 0x1f, 0x80, 0x22, 0, n} }
	devs := []Device{
		{MAC: macStr(mac(1)), Name: "bp-a", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: macStr(mac(2)), Name: "bp-b", Model: "MCXi", Version: "5.0.7.9165"},
		{MAC: macStr(mac(3)), Name: "bp-c", Model: "MCXi", Version: "5.0.4.5846"},
		{MAC: macStr(mac(4)), Name: "wp-a", Model: "WPXi", Version: "5.0.7.9165"},
	}
	// Within-family release skew is caught by the same fleet-wide check.
	sp := ReleaseMismatch(devs)
	if sp == nil {
		t.Fatal("diverging fleet yielded no finding")
	}
	if len(sp.Releases) != 2 || sp.Releases[0].Release != "5.0.7" || sp.Releases[0].N != 3 {
		t.Errorf("releases = %+v, want majority 5.0.7 x3 first", sp.Releases)
	}
	if len(sp.Devices) != 4 {
		t.Errorf("devices = %d, want 4", len(sp.Devices))
	}

	// A fully uniform fleet produces no mismatch.
	if got := ReleaseMismatch(devs[:2]); got != nil {
		t.Errorf("uniform fleet returned %+v, want nil", got)
	}
}

// TestOnlyEmitsScanAndReboot is the safety guard: this package builds exactly two
// frames - the read-only scan request and the reboot request SendReboot uses - and
// no third emitter. The scan frame is pinned byte-for-byte, and the reboot frame is
// held to the same fixed shape differing in exactly one request byte, so a new frame
// can't be introduced here unnoticed.
func TestOnlyEmitsScanAndReboot(t *testing.T) {
	wantScan := []byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x10, 0x00, 0x00}
	if !bytes.Equal(scanFrame, wantScan) {
		t.Fatalf("scanFrame = % x, want % x", scanFrame, wantScan)
	}
	if len(rebootFrame) != len(scanFrame) {
		t.Fatalf("rebootFrame len = %d, want %d", len(rebootFrame), len(scanFrame))
	}
	diff := 0
	for i := range scanFrame {
		if rebootFrame[i] != scanFrame[i] {
			diff++
		}
	}
	if diff != 1 {
		t.Fatalf("reboot frame differs from scan in %d byte(s), want exactly 1", diff)
	}
}

// frameDeclRe matches a package-level fixed frame literal declaration.
var frameDeclRe = regexp.MustCompile(`(?m)^var (\w+) = \[\]byte\{`)

// sendCallRe matches a WriteToUDP call whose payload is a bare identifier.
var sendCallRe = regexp.MustCompile(`WriteToUDP\((\w+),`)

// TestNoUndeclaredEmitter is a best-effort source tripwire, not a proof. It scans
// scan.go and checks that exactly two frame literals are declared (scanFrame,
// rebootFrame) and that every WriteToUDP call it can see transmits one of them. This
// catches the common accidental mistake - a new frame variable sent from a new
// WriteToUDP call site. Because it is a regex over one file, it does NOT rule out an
// inline []byte{...} payload, a send through another method (Write/WriteMsgUDP), or a
// call added in a different file in the package. It narrows the gap, it does not close
// it; the byte-pinned frame checks above remain the real guarantee about frame content.
func TestNoUndeclaredEmitter(t *testing.T) {
	src, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatalf("read scan.go: %v", err)
	}

	declared := map[string]bool{}
	for _, m := range frameDeclRe.FindAllStringSubmatch(string(src), -1) {
		declared[m[1]] = true
	}
	if len(declared) != 2 || !declared["scanFrame"] || !declared["rebootFrame"] {
		t.Fatalf("declared frame literals = %v, want exactly {scanFrame, rebootFrame}", declared)
	}

	sends := sendCallRe.FindAllStringSubmatch(string(src), -1)
	if len(sends) == 0 {
		t.Fatal("found no send call sites - the matcher is stale, tighten it before trusting this guard")
	}
	sentScan, sentReboot := false, false
	for _, m := range sends {
		payload := m[1]
		if !declared[payload] {
			t.Errorf("send call transmits %q, which is not one of the two pinned frames", payload)
		}
		switch payload {
		case "scanFrame":
			sentScan = true
		case "rebootFrame":
			sentReboot = true
		}
	}
	if !sentScan || !sentReboot {
		t.Errorf("expected both frames to be sent (scan=%v reboot=%v)", sentScan, sentReboot)
	}
}

// macStr formats 6 bytes as a colon-separated MAC for building test devices by value.
func macStr(b [6]byte) string { return net.HardwareAddr(b[:]).String() }
