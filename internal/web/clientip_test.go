package web

import (
	"net/http"
	"testing"
)

// clientIP must read the RIGHT-MOST X-Forwarded-For hop when the immediate peer is
// loopback (the trusted Caddy proxy), so a client-forged left-most entry can't pick
// its own throttle bucket. A non-loopback peer ignores XFF entirely.
func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"loopback, single hop", "127.0.0.1:5000", "203.0.113.7", "203.0.113.7"},
		{"loopback, forged left-most", "127.0.0.1:5000", "1.2.3.4, 203.0.113.7", "203.0.113.7"},
		{"loopback, multi forged", "127.0.0.1:5000", "9.9.9.9, 8.8.8.8, 203.0.113.7", "203.0.113.7"},
		{"loopback, spaces", "127.0.0.1:5000", " 203.0.113.7 ", "203.0.113.7"},
		{"loopback, no xff falls back to peer", "127.0.0.1:5000", "", "127.0.0.1"},
		{"non-loopback ignores xff", "203.0.113.50:5000", "1.2.3.4", "203.0.113.50"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tc.remoteAddr, Header: http.Header{}}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP(%q, xff=%q) = %q, want %q", tc.remoteAddr, tc.xff, got, tc.want)
			}
		})
	}
}
