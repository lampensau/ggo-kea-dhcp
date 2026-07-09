package appliance

import (
	"strings"
	"testing"
)

// isPrintableASCII is a pure character-set predicate: the empty string is
// vacuously printable (true), and the callers that need empty to mean
// "fall back to hex" check s != "" explicitly (renderIDPart,
// bytesToPortIdentity). This table pins both halves of that contract.
func TestIsPrintableASCII(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"Gi0/1", true},
		{"", true},        // vacuously true: empty-string policy lives at the call sites
		{"a\x01b", false}, // control char
		{"a\x7fb", false}, // DEL
		{"gültig", false}, // multibyte UTF-8: every byte >= 0x80 fails
	} {
		if got := isPrintableASCII(c.in); got != c.want {
			t.Errorf("isPrintableASCII(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	// The two ex-isPrintable call sites must still treat empty/NUL-only input as
	// non-printable (hex fallback), not vacuously printable.
	if ascii, hexStr := renderIDPart([]byte{0, 0}); ascii != hexStr {
		t.Errorf("renderIDPart(NUL-only) ascii=%q, want hex fallback %q", ascii, hexStr)
	}
	if got := BytesToPortIdentity(nil); got != "" {
		t.Errorf("BytesToPortIdentity(nil) = %q, want empty", got)
	}
}

func TestDecodePortIdentity(t *testing.T) {
	// Kea client-ids carry the replace-client-id 0x00 prefix; decodePortIdentity
	// strips it, then splits the flex-id on the 0x1f delimiter the identifier-
	// expression inserts between remote-id and circuit-id. Mikrotik case: remote-id
	// "AV-Edge-1", circuit-id "ether7" (neither contains a slash) - both must decode
	// to readable ASCII, not a hex chain. client-id =
	//   00 + hex("AV-Edge-1") + 1f + hex("ether7")
	id, ok := DecodePortIdentity("0041562d456467652d311f657468657237")
	if !ok || id.RemoteID != "AV-Edge-1" || id.CircuitID != "ether7" {
		t.Errorf("decodePortIdentity mikrotik = %+v ok=%v, want remote AV-Edge-1 / circuit ether7", id, ok)
	}
	// The opaque Key carries the 0x1f delimiter, so it renders as colon-hex and
	// round-trips through flexIDToBytes back to the same reservation bytes.
	if !strings.Contains(id.Key, ":") {
		t.Errorf("delimited flex-id Key = %q, want colon-hex", id.Key)
	}
	if got := string(FlexIDToBytes(id.Key)); got != "AV-Edge-1\x1fether7" {
		t.Errorf("Key round-trip = %q, want AV-Edge-1\\x1fether7", got)
	}
	// A binary flex-id with no delimiter surfaces as colon-hex under remote-id.
	id, ok = DecodePortIdentity("0001ff")
	if !ok || id.Key != "01:ff" || id.RemoteID != "01:ff" || id.CircuitID != "" {
		t.Errorf("decodePortIdentity binary = %+v ok=%v, want Key 01:ff / remote 01:ff / circuit ''", id, ok)
	}
	// A normal client-id (0x01 + MAC, no Option-82) is NOT a port -> ok=false.
	if _, ok := DecodePortIdentity("01c8ffbf0e6fe6"); ok {
		t.Error("decodePortIdentity should reject a normal 0x01-type client-id (not an Option-82 port)")
	}
	// Empty and 0x00-only ids are not ports either.
	if _, ok := DecodePortIdentity(""); ok {
		t.Error("decodePortIdentity should reject an empty client-id")
	}
	if _, ok := DecodePortIdentity("00"); ok {
		t.Error("decodePortIdentity should reject a 0x00-only (empty flex-id) client-id")
	}
}

func TestRenderIDPart(t *testing.T) {
	cases := []struct {
		name      string
		in        []byte
		wantASCII string
		wantHex   string
	}{
		{"empty", nil, "", ""},
		{"printable", []byte("ether7"), "ether7", "65:74:68:65:72:37"},
		{"nul-padded ascii", []byte("ether7\x00\x00"), "ether7", "65:74:68:65:72:37:00:00"},
		{"binary interior", []byte{0x00, 0x14, 0x03}, "00:14:03", "00:14:03"},
		{"binary high bit", []byte{0xde, 0xad}, "de:ad", "de:ad"},
		{"all nul", []byte{0x00, 0x00}, "00:00", "00:00"},
	}
	for _, c := range cases {
		ascii, hexStr := renderIDPart(c.in)
		if ascii != c.wantASCII || hexStr != c.wantHex {
			t.Errorf("%s: renderIDPart=(%q,%q), want (%q,%q)", c.name, ascii, hexStr, c.wantASCII, c.wantHex)
		}
	}
}

func TestDecodeHex(t *testing.T) {
	if got := decodeHex("4869"); got != "Hi" {
		t.Errorf("decodeHex(4869)=%q want Hi", got)
	}
	if got := decodeHex("48:69"); got != "Hi" {
		t.Errorf("decodeHex with colons =%q want Hi", got)
	}
	if got := decodeHex("zzz"); got != "zzz" {
		t.Errorf("decodeHex(invalid) =%q want passthrough", got)
	}
}
