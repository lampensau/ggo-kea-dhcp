package kea

import "testing"

func TestNormalizeOUI6(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"00:1f:80", "001f80"},          // colons stripped, lowercased
		{"001F80", "001f80"},            // uppercase
		{"00:1f:80:12:34:56", "001f80"}, // truncated to first 6 hex
		{"001f8", ""},                   // fewer than 6 hex -> empty
		{"", ""},                        // empty
		{"zz:1f:80:aa", "1f80aa"},       // non-hex skipped
	}
	for _, c := range cases {
		if got := NormalizeOUI6(c.in); got != c.want {
			t.Errorf("NormalizeOUI6(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
