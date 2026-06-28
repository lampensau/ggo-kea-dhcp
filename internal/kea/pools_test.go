package kea

import (
	"net"
	"testing"
)

func TestDynamicPoolRange(t *testing.T) {
	cases := []struct {
		cidr, want string
	}{
		{"10.0.0.0/24", "10.0.0.10 - 10.0.0.254"}, // common case unchanged
		{"10.0.0.0/28", "10.0.0.10 - 10.0.0.14"},  // .10 start still fits
		{"10.0.0.0/29", "10.0.0.4 - 10.0.0.6"},    // clamped: .10 would be out of subnet
		{"10.0.0.0/30", "10.0.0.2 - 10.0.0.2"},    // clamped to a single in-subnet address
	}
	for _, c := range cases {
		_, ipnet, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", c.cidr, err)
		}
		if got := DynamicPoolRange(ipnet); got != c.want {
			t.Errorf("DynamicPoolRange(%s)=%q want %q", c.cidr, got, c.want)
		}
	}
}
