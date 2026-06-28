package web

import "testing"

func TestValidVLANID(t *testing.T) {
	cases := []struct {
		v    int
		want bool
	}{
		{-1, false},
		{0, true}, // untagged scope
		{1, true},
		{4094, true},
		{4095, false}, // reserved
		{9000, false},
	}
	for _, c := range cases {
		if got := validVLANID(c.v); got != c.want {
			t.Errorf("validVLANID(%d) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestValidateUplink(t *testing.T) {
	cases := []struct {
		name     string
		ssid     string
		password string
		wantOK   bool // true means "" (valid)
	}{
		{"valid with password", "GreenGo-Uplink", "supersecret", true},
		{"valid open network", "OpenAP", "", true},
		{"empty ssid", "", "supersecret", false},
		{"ssid too long", "this-ssid-is-way-too-long-to-be-valid-x", "secret12", false},
		{"ssid control char", "bad\nssid", "secret12", false},
		{"password too short", "AP", "short", false},
		{"password too long", "AP", string(make([]byte, 64)), false},
		{"password control char", "AP", "secret\x00pass", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := validateUplink(c.ssid, c.password)
			if (msg == "") != c.wantOK {
				t.Errorf("validateUplink(%q,%q) = %q, wantOK=%v", c.ssid, c.password, msg, c.wantOK)
			}
		})
	}
}

func TestClassCodes(t *testing.T) {
	if got := classCodes("GGO-BPX"); got != "BPX / BP2" {
		t.Errorf("classCodes(GGO-BPX) = %q, want %q", got, "BPX / BP2")
	}
	if got := classCodes("GGO-STRIDE"); got != "STRIDE" {
		t.Errorf("classCodes(GGO-STRIDE) = %q, want %q", got, "STRIDE")
	}
	// Catch-all / unknown classes have no codes.
	if got := classCodes(""); got != "" {
		t.Errorf("classCodes(\"\") = %q, want empty", got)
	}
	if got := classCodes("GGO-UNKNOWN"); got != "" {
		t.Errorf("classCodes(GGO-UNKNOWN) = %q, want empty", got)
	}
}
