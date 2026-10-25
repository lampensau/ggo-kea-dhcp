package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestReservationTarget proves the reservation/pin matcher maps an IP to the active
// profile's (scope index + 1) Kea subnet-id, fails closed for an IP outside every
// configured scope or with no active profile, and refuses the addresses no device may
// hold - the network, the broadcast and the appliance's own address (network+1).
func TestReservationTarget(t *testing.T) {
	s, _ := newTestServer(t)

	// No active profile: every IP is refused.
	if _, err := s.reservationTarget()(net.ParseIP("10.0.0.5")); err == nil {
		t.Fatal("reservationTarget should fail closed with no active profile")
	}

	res, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('p', 1)")
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	for _, cidr := range []string{"10.0.0.0/24", "192.168.1.0/24"} {
		if _, err := s.sqlite.Exec(
			"INSERT INTO scopes (profile_id, vlan_id, cidr, preset) VALUES (?,0,?,'greengo')",
			pid, cidr); err != nil {
			t.Fatalf("seed scope %s: %v", cidr, err)
		}
	}
	m := s.reservationTarget()
	cases := []struct {
		ip      string
		want    int
		errPart string // "" = accepted
	}{
		{"10.0.0.5", 1, ""},    // scope index 0 -> subnet-id 1
		{"192.168.1.9", 2, ""}, // scope index 1 -> subnet-id 2
		{"10.0.0.2", 1, ""},    // first pool address is fine
		{"10.0.0.254", 1, ""},  // last host address is fine
		{"8.8.8.8", 0, "not inside any configured subnet"},
		{"10.0.0.1", 0, "appliance's own address"},
		{"192.168.1.1", 0, "appliance's own address"},
		{"10.0.0.0", 0, "network address"},
		{"10.0.0.255", 0, "broadcast address"},
	}
	for _, c := range cases {
		got, err := m(net.ParseIP(c.ip))
		switch {
		case c.errPart == "" && (err != nil || got != c.want):
			t.Errorf("matcher(%s) = (%d, %v), want (%d, nil)", c.ip, got, err, c.want)
		case c.errPart != "" && (err == nil || !strings.Contains(err.Error(), c.errPart)):
			t.Errorf("matcher(%s) error = %v, want one mentioning %q", c.ip, err, c.errPart)
		}
	}
}

// The pin handler routes the dialog's (operator-editable) IP through reservationTarget,
// so pinning a port to the appliance's own address is refused with that reason before
// anything is written - a pin here would hand the box's address to a device.
func TestHandlePinRefusesApplianceAddress(t *testing.T) {
	s, _ := newTestServer(t)
	seedScopePreset(t, s, "greengo") // 10.0.0.0/24, appliance at 10.0.0.1

	form := url.Values{"port_identity": {"41561f"}, "ip": {"10.0.0.1"}}
	req := httptest.NewRequest("POST", "/pinning/pin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handlePin(rr, req)

	c := flashCookie(rr)
	if c == nil {
		t.Fatal("no flash cookie set")
	}
	req2 := httptest.NewRequest("GET", "/pinning", nil)
	req2.AddCookie(&http.Cookie{Name: "ggo_flash", Value: c.Value})
	if f := s.getFlash(httptest.NewRecorder(), req2); f == nil || f.Type != "error" || !strings.Contains(f.Message, "appliance's own address") {
		t.Fatalf("flash = %+v, want the appliance-address refusal", f)
	}
}
