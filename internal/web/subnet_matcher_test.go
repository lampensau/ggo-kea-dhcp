package web

import (
	"net"
	"testing"
)

// TestImportSubnetMatcher proves the bulk-import matcher maps an IP to the active
// profile's (scope index + 1) Kea subnet-id and fails closed (0,false) for an IP
// outside every configured scope - the same mapping subnetIDForIP uses, resolved once.
func TestImportSubnetMatcher(t *testing.T) {
	s, _ := newTestServer(t)
	res, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('p', 1)")
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	for _, cidr := range []string{"10.0.0.0/24", "192.168.1.0/24"} {
		if _, err := s.sqlite.Exec(
			"INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset) VALUES (?,'physical',0,?,'greengo')",
			pid, cidr); err != nil {
			t.Fatalf("seed scope %s: %v", cidr, err)
		}
	}
	m := s.importSubnetMatcher()
	cases := []struct {
		ip   string
		want int
		ok   bool
	}{
		{"10.0.0.5", 1, true},    // scope index 0 -> subnet-id 1
		{"192.168.1.9", 2, true}, // scope index 1 -> subnet-id 2
		{"8.8.8.8", 0, false},    // outside every scope -> fail closed
	}
	for _, c := range cases {
		got, ok := m(net.ParseIP(c.ip))
		if got != c.want || ok != c.ok {
			t.Errorf("matcher(%s) = (%d,%v), want (%d,%v)", c.ip, got, ok, c.want, c.ok)
		}
	}
}
