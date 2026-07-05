package preflight

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ggo-kea-dhcp/internal/config"
)

func TestResultHasFailure(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want bool
	}{
		{"empty", Result{}, false},
		{"all ok", Result{{Status: OK}, {Status: OK}}, false},
		{"warn only", Result{{Status: OK}, {Status: Warn}}, false},
		{"one fail", Result{{Status: OK}, {Status: Fail}, {Status: Warn}}, true},
	}
	for _, c := range cases {
		if got := c.r.HasFailure(); got != c.want {
			t.Errorf("%s: HasFailure()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestResultWorst(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want Status
	}{
		{"empty -> OK", Result{}, OK},
		{"all ok", Result{{Status: OK}}, OK},
		{"warn beats ok", Result{{Status: OK}, {Status: Warn}}, Warn},
		{"fail beats warn", Result{{Status: Warn}, {Status: Fail}, {Status: OK}}, Fail},
	}
	for _, c := range cases {
		if got := c.r.Worst(); got != c.want {
			t.Errorf("%s: Worst()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestClockStatus(t *testing.T) {
	// Only "no RTC AND not synced" is risky; a present RTC is OK regardless of NTP.
	cases := []struct {
		rtc, synced bool
		want        Status
	}{
		{true, true, OK},
		{true, false, OK},    // RTC alone is enough - no forward step to fear
		{false, true, OK},    // no RTC but disciplined + fake-hwclock persists it
		{false, false, Warn}, // the lease-wipe-prone state
	}
	for _, c := range cases {
		if got := clockStatus(c.rtc, c.synced); got.Status != c.want {
			t.Errorf("clockStatus(rtc=%v, synced=%v)=%v want %v", c.rtc, c.synced, got.Status, c.want)
		}
	}
}

func TestCapCheck(t *testing.T) {
	// bit 13 (CAP_NET_RAW) held -> OK; absent -> Warn.
	const bit = 13
	held := capCheck("x", uint64(1)<<bit, bit)
	if held.Status != OK {
		t.Errorf("held cap: status=%v want OK", held.Status)
	}
	absent := capCheck("x", 0, bit)
	if absent.Status != Warn {
		t.Errorf("absent cap: status=%v want Warn", absent.Status)
	}
	// A different bit set must not be mistaken for this one (catches & vs |).
	other := capCheck("x", uint64(1)<<(bit+1), bit)
	if other.Status != Warn {
		t.Errorf("wrong bit set: status=%v want Warn", other.Status)
	}
}

func TestKeaBinaryStatus(t *testing.T) {
	cases := []struct {
		name      string
		installed bool
		version   string
		verr      error
		want      Status
	}{
		{"not installed", false, "", nil, Fail},
		{"version unreadable", true, "", errors.New("exec"), Warn},
		{"unsupported 2.x", true, "2.6.1", nil, Fail},
		{"unsupported 3.2", true, "3.2.0", nil, Fail},
		{"supported 3.0.x", true, "3.0.4", nil, OK},
	}
	for _, c := range cases {
		if got := keaBinaryStatus(c.installed, c.version, c.verr); got.Status != c.want {
			t.Errorf("%s: status=%v want %v (%s)", c.name, got.Status, c.want, got.Detail)
		}
	}
	// The remediation detail is what the installer output shows the operator -
	// pin the two actionable ones.
	if got := keaBinaryStatus(false, "", nil); !strings.Contains(got.Detail, "isc-kea-dhcp4-server") {
		t.Errorf("not-installed detail %q does not name the package to install", got.Detail)
	}
	if got := keaBinaryStatus(true, "2.6.1", nil); !strings.Contains(got.Detail, "3.0.x") {
		t.Errorf("wrong-series detail %q does not name the required series", got.Detail)
	}
}

func TestHooksStatus(t *testing.T) {
	if got := hooksStatus("/usr/lib/hooks/", nil); got.Status != OK || got.Detail != "all present in /usr/lib/hooks" {
		t.Errorf("all present = %v %q, want the trailing slash trimmed", got.Status, got.Detail)
	}
	got := hooksStatus("/usr/lib/hooks", []string{"libdhcp_flex_id.so"})
	if got.Status != Fail || !strings.Contains(got.Detail, "libdhcp_flex_id.so") {
		t.Errorf("missing hook = %v %q, want Fail naming the library", got.Status, got.Detail)
	}
}

func TestKeaSocketStatus(t *testing.T) {
	if got := keaSocketStatus("http://x:8004/", errors.New("no secret"), nil); got.Status != Warn {
		t.Errorf("secret error = %v, want Warn", got.Status)
	}
	if got := keaSocketStatus("http://x:8004/", nil, errors.New("refused")); got.Status != Warn {
		t.Errorf("ping error = %v, want Warn", got.Status)
	}
	if got := keaSocketStatus("http://x:8004/", nil, nil); got.Status != OK {
		t.Errorf("reachable = %v, want OK", got.Status)
	}
}

func TestToolStatus(t *testing.T) {
	if got := toolStatus("nmcli", true); got.Status != OK || got.Name != "Tool: nmcli" {
		t.Errorf("present tool = %+v", got)
	}
	if got := toolStatus("nft", false); got.Status != Fail {
		t.Errorf("absent tool = %v, want Fail (installer gate)", got.Status)
	}
}

func TestMariadbStatus(t *testing.T) {
	// Warn throughout - dynamic leases must keep serving without reservations.
	if got := mariadbStatus("u:p@tcp(h)/kea", errors.New("refused"), nil); got.Status != Warn {
		t.Errorf("connect error = %v, want Warn", got.Status)
	}
	if got := mariadbStatus("u:p@tcp(h)/kea", nil, errors.New("no hosts table")); got.Status != Warn {
		t.Errorf("schema error = %v, want Warn", got.Status)
	}
	got := mariadbStatus("u:secret@tcp(h)/kea", nil, nil)
	if got.Status != OK {
		t.Errorf("healthy = %v, want OK", got.Status)
	}
	if strings.Contains(got.Detail, "secret") {
		t.Errorf("healthy detail leaks the DSN password: %q", got.Detail)
	}
}

func TestCapsStatus(t *testing.T) {
	if got := capsStatus(0, errors.New("unreadable")); len(got) != 1 || got[0].Status != Warn {
		t.Errorf("read error = %+v, want one Warn", got)
	}
	both := capsStatus(1<<capNetRaw|1<<capNetBindService, nil)
	if len(both) != 2 || both[0].Status != OK || both[1].Status != OK {
		t.Errorf("both caps held = %+v", both)
	}
	none := capsStatus(0, nil)
	if len(none) != 2 || none[0].Status != Warn || none[1].Status != Warn {
		t.Errorf("no caps = %+v, want two Warns (degraded, never Fail)", none)
	}
}

func TestPort53Status(t *testing.T) {
	if got := port53Status(nil); got.Status != OK {
		t.Errorf("bind ok = %v, want OK", got.Status)
	}
	perm := port53Status(&net.OpError{Op: "listen", Err: os.ErrPermission})
	if perm.Status != Warn || !strings.Contains(perm.Detail, "CAP_NET_BIND_SERVICE") {
		t.Errorf("permission = %v %q, want the capability story", perm.Status, perm.Detail)
	}
	taken := port53Status(errors.New("address already in use"))
	if taken.Status != Warn || !strings.Contains(taken.Detail, "taken") {
		t.Errorf("in use = %v %q, want the port-taken story", taken.Status, taken.Detail)
	}
}

// checkKeaConfDir runs against the real filesystem, so exercise all four paths
// with temp dirs. Writability of an existing conf is probed on THAT file (the
// dir itself is deliberately root-owned in production).
func TestCheckKeaConfDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("read-only permission probes are meaningless as root")
	}
	t.Run("existing conf writable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "kea-dhcp4.conf"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		if got := checkKeaConfDir(&config.Config{KeaConfDir: dir}); got.Status != OK {
			t.Errorf("writable conf = %v (%s)", got.Status, got.Detail)
		}
	})
	t.Run("existing conf read-only", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "kea-dhcp4.conf"), []byte("{}"), 0400); err != nil {
			t.Fatal(err)
		}
		if got := checkKeaConfDir(&config.Config{KeaConfDir: dir}); got.Status != Fail {
			t.Errorf("read-only conf = %v (%s), want Fail", got.Status, got.Detail)
		}
	})
	t.Run("no conf, dir writable", func(t *testing.T) {
		if got := checkKeaConfDir(&config.Config{KeaConfDir: t.TempDir()}); got.Status != OK {
			t.Errorf("writable dir = %v (%s)", got.Status, got.Detail)
		}
	})
	t.Run("no conf, dir read-only", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
		if got := checkKeaConfDir(&config.Config{KeaConfDir: dir}); got.Status != Fail {
			t.Errorf("read-only dir = %v (%s), want Fail", got.Status, got.Detail)
		}
	})
}

// Run must return a stable, fully-populated result whatever the host looks
// like - the Diagnostics page and the installer both consume it blind.
func TestRunShape(t *testing.T) {
	dir := t.TempDir()
	r := Run(&config.Config{
		KeaConfDir:    dir,
		KeaSecretPath: filepath.Join(dir, "no-secret"),
		KeaAPIURL:     "http://127.0.0.1:1/",
		MariaDBDSN:    "u:p@tcp(127.0.0.1:1)/kea",
	})
	// Exact count: 4 Kea + 6 tools + MariaDB + 2 caps + port 53 + clock. A loose
	// floor would let a third of the probe set vanish unnoticed.
	if len(r) != 15 {
		t.Fatalf("Run returned %d checks, want the full probe set of 15", len(r))
	}
	for i, c := range r {
		if c.Name == "" || c.Detail == "" {
			t.Errorf("check %d has empty name/detail: %+v", i, c)
		}
		switch c.Status {
		case OK, Warn, Fail:
		default:
			t.Errorf("check %q has invalid status %q", c.Name, c.Status)
		}
	}
	if r[0].Name != "Kea binary" {
		t.Errorf("first check = %q, want the Kea binary (stable order)", r[0].Name)
	}
}
