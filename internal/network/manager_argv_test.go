package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestartService(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.RestartService("kea-dhcp4"); err != nil {
		t.Fatalf("RestartService: %v", err)
	}
	if !callContaining(rec, "systemctl", "restart", "kea-dhcp4") {
		t.Errorf("calls=%v", rec.Calls)
	}
}

func TestSetInterfaceManaged(t *testing.T) {
	for _, c := range []struct {
		managed bool
		want    string
	}{{true, "yes"}, {false, "no"}} {
		rec := &RecordingCommander{}
		m := NewManagerWithCommander(rec)
		if err := m.SetInterfaceManaged("wlan0", c.managed); err != nil {
			t.Fatalf("SetInterfaceManaged(%v): %v", c.managed, err)
		}
		if !callContaining(rec, "nmcli", "device", "set", "wlan0", "managed", c.want) {
			t.Errorf("managed=%v: want %q, calls=%v", c.managed, c.want, rec.Calls)
		}
	}
}

func TestDeleteApplianceConnections(t *testing.T) {
	// Only ggo-* connections may be torn down; a foreign connection must be left alone.
	// The inactive ggo-eth0.20 (DEVICE "--") must be deleted too, so the listing must
	// not be filtered with --active.
	rec := &RecordingCommander{Outputs: map[string]string{
		"nmcli": "ggo-eth0           uuid1  ethernet  eth0\n" +
			"Wired connection 1  uuid2  ethernet  eth1\n" +
			"ggo-eth0.20         uuid4  vlan      --\n" +
			"ggo-wifi-uplink     uuid3  wifi      wlan0\n",
	}}
	m := NewManagerWithCommander(rec)
	if err := m.DeleteApplianceConnections(); err != nil {
		t.Fatalf("DeleteApplianceConnections: %v", err)
	}
	for _, name := range []string{"ggo-eth0", "ggo-eth0.20", "ggo-wifi-uplink"} {
		if !callContaining(rec, "connection", "delete", name) {
			t.Errorf("expected delete of %s, calls=%v", name, rec.Calls)
		}
	}
	if callContaining(rec, "connection", "delete", "Wired") {
		t.Errorf("foreign connection must not be deleted, calls=%v", rec.Calls)
	}
	// The teardown must enumerate all connections, not just active ones, or inactive
	// ggo-* connections survive and later autoconnect with stale addressing.
	if callContaining(rec, "connection", "show", "--active") {
		t.Errorf("teardown must list all connections, not --active only; calls=%v", rec.Calls)
	}
}

func TestIsWifiUplinkActive(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"activated", "ggo-wifi-uplink:activated", true},
		{"activating not enough", "ggo-wifi-uplink:activating", false}, // must require activated
		{"other connection", "ggo-eth0:activated", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &RecordingCommander{Outputs: map[string]string{"nmcli": c.out}}
			m := NewManagerWithCommander(rec)
			if got := m.IsWifiUplinkActive(); got != c.want {
				t.Errorf("IsWifiUplinkActive()=%v want %v (out=%q)", got, c.want, c.out)
			}
		})
	}
}

// ServiceLogTail must issue exactly the argv the sudoers drop-in whitelists -
// and the drop-in must actually contain that line, so a drift between the two
// fails here instead of only on the Pi.
func TestServiceLogTailArgvMatchesSudoers(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if _, err := m.ServiceLogTail(); err != nil {
		t.Fatalf("ServiceLogTail: %v", err)
	}
	want := "journalctl -u ggo-kea-dhcp -n 200 --no-pager"
	if !callContaining(rec, "journalctl", "-u", "ggo-kea-dhcp", "-n", "200", "--no-pager") {
		t.Errorf("argv drifted from the sudoers rule %q; calls=%v", want, rec.Calls)
	}
	sudoers, err := os.ReadFile(filepath.Join("..", "..", "packaging", "sudoers", "ggo-kea-dhcp"))
	if err != nil {
		t.Fatalf("read sudoers drop-in: %v", err)
	}
	if !strings.Contains(string(sudoers), want) {
		t.Errorf("packaging/sudoers/ggo-kea-dhcp lacks the exact-argument line %q", want)
	}
}
