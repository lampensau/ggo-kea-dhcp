package web

import (
	"net"
	"net/url"
	"testing"

	"ggo-kea-dhcp/internal/ggoscan"
	"ggo-kea-dhcp/internal/netmon"
	"ggo-kea-dhcp/internal/web/views"
)

// hexLEtoIP converts /proc/net/route little-endian hex to a dotted IPv4. The byte
// order is the easy thing to get backwards, so the happy-path case pins it.
func TestHexLEtoIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"0100A8C0", "192.168.0.1"}, // C0=192 A8=168 00=0 01=1, reversed
		{"0101A8C0", "192.168.1.1"},
		{"00000000", ""}, // default route / 0.0.0.0 -> filtered
		{"0100A8", ""},   // wrong length
		{"ZZ00A8C0", ""}, // non-hex
		{"", ""},         // empty
	}
	for _, c := range cases {
		if got := hexLEtoIP(c.in); got != c.want {
			t.Errorf("hexLEtoIP(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSysHealthSeverity(t *testing.T) {
	// thresholds: warn>=80, err>=92; severity is the worst of the three.
	cases := []struct {
		cpu, mem, disk int
		want           string
	}{
		{10, 20, 30, "ok"},
		{79, 79, 79, "ok"},
		{80, 0, 0, "warn"}, // boundary: >=80 is warn
		{0, 91, 0, "warn"},
		{0, 0, 92, "err"},   // boundary: >=92 is err
		{50, 95, 50, "err"}, // worst wins
	}
	for _, c := range cases {
		if got := sysHealthSeverity(c.cpu, c.mem, c.disk); got != c.want {
			t.Errorf("sysHealthSeverity(%d,%d,%d)=%q want %q", c.cpu, c.mem, c.disk, got, c.want)
		}
	}
}

func TestClampPercent(t *testing.T) {
	cases := []struct{ in, want int }{
		{-5, 0}, {0, 0}, {50, 50}, {100, 100}, {150, 100},
	}
	for _, c := range cases {
		if got := clampPercent(c.in); got != c.want {
			t.Errorf("clampPercent(%d)=%d want %d", c.in, got, c.want)
		}
	}
}

func TestParseMeminfoKB(t *testing.T) {
	cases := []struct {
		line   string
		want   uint64
		wantOK bool
	}{
		{"MemTotal:       16331756 kB", 16331756, true},
		{"MemAvailable:    8000000 kB", 8000000, true},
		{"MemTotal:", 0, false}, // no value field
		{"MemTotal:   notanumber kB", 0, false},
	}
	for _, c := range cases {
		got, ok := parseMeminfoKB(c.line)
		if got != c.want || ok != c.wantOK {
			t.Errorf("parseMeminfoKB(%q)=(%d,%v) want (%d,%v)", c.line, got, ok, c.want, c.wantOK)
		}
	}
}

func TestRowSeverityRank(t *testing.T) {
	// error sorts first (0), unknown/info last (3).
	cases := []struct {
		sev  string
		want int
	}{
		{"error", 0}, {"warn", 1}, {"ok", 2}, {"info", 3}, {"", 3}, {"bogus", 3},
	}
	for _, c := range cases {
		if got := rowSeverityRank(c.sev); got != c.want {
			t.Errorf("rowSeverityRank(%q)=%d want %d", c.sev, got, c.want)
		}
	}
}

func TestDetectorKindOrder(t *testing.T) {
	// DHCP-integrity detectors must sort ahead of the fabric ones, unknown last.
	if detectorKindOrder("rogue_dhcp") >= detectorKindOrder("greengo") {
		t.Error("rogue_dhcp should rank before greengo")
	}
	if detectorKindOrder("duplicate_ip") >= detectorKindOrder("vlan") {
		t.Error("duplicate_ip should rank before vlan")
	}
	if got := detectorKindOrder("nonexistent"); got != 99 {
		t.Errorf("unknown kind = %d want 99", got)
	}
}

func TestSeverityDot(t *testing.T) {
	cases := []struct {
		sev  netmon.Severity
		want string
	}{
		{netmon.SevError, "err"},
		{netmon.SevWarn, "warn"},
		{netmon.SevOK, "ok"},
		{netmon.SevInfo, ""},
	}
	for _, c := range cases {
		if got := severityDot(c.sev); got != c.want {
			t.Errorf("severityDot(%v)=%q want %q", c.sev, got, c.want)
		}
	}
}

func TestLevelNote(t *testing.T) {
	if levelNote(netmon.LevelFull) != "" {
		t.Error("full level should have no banner")
	}
	for _, lvl := range []netmon.Level{netmon.LevelNoPromisc, netmon.LevelCountersOnly, netmon.LevelPaused} {
		if levelNote(lvl) == "" {
			t.Errorf("degraded level %v should have a banner", lvl)
		}
	}
}

func TestNetHealthDetail(t *testing.T) {
	rogue := netmon.DetectorSnapshot{
		Kind: "rogue_dhcp", Subject: "eth0",
		Fields: map[string]string{"mac": "aa:bb:cc:dd:ee:ff", "server": "10.0.0.9"},
	}
	if got := netHealthDetail(rogue); got != "server 10.0.0.9 · aa:bb:cc:dd:ee:ff · on eth0" {
		t.Errorf("rogue detail = %q", got)
	}

	// greengo_config with no config heard yet must emit nothing (not a bare "config ").
	empty := netmon.DetectorSnapshot{Kind: "greengo_config", Fields: map[string]string{}}
	if got := netHealthDetail(empty); got != "" {
		t.Errorf("empty greengo_config detail = %q want empty", got)
	}

	// A snapshot with a nil Fields map must not panic.
	nilFields := netmon.DetectorSnapshot{Kind: "rogue_dhcp", Subject: "eth0"}
	if got := netHealthDetail(nilFields); got != "" {
		t.Errorf("nil-fields detail = %q want empty", got)
	}
}

func TestAtoiDefault(t *testing.T) {
	cases := []struct {
		s    string
		def  int
		want int
	}{
		{"42", 7, 42}, {"", 7, 7}, {"x", 7, 7}, {"-3", 0, -3},
	}
	for _, c := range cases {
		if got := atoiDefault(c.s, c.def); got != c.want {
			t.Errorf("atoiDefault(%q,%d)=%d want %d", c.s, c.def, got, c.want)
		}
	}
}

func TestFmtTip(t *testing.T) {
	cases := []struct {
		v    int
		unit string
		want string
	}{
		{12, "", "12"},
		{82, "%", "82%"},
		{12, "ms", "12 ms"},
	}
	for _, c := range cases {
		if got := fmtTip(c.v, c.unit); got != c.want {
			t.Errorf("fmtTip(%d,%q)=%q want %q", c.v, c.unit, got, c.want)
		}
	}
}

func TestUplinkTips(t *testing.T) {
	// -1 sentinel must render "offline", never "-1 ms".
	got := uplinkTips([]int{5, -1, 12})
	if got != "5 ms|offline|12 ms" {
		t.Errorf("uplinkTips = %q", got)
	}
}

func TestPtpTips(t *testing.T) {
	// -1 -> "absent"; non-negative -> the PTPQuality label for that clockClass.
	series := []int{-1, 6}
	wantLabel, _ := views.PTPQuality(6)
	got := ptpTips(series)
	if got != "absent|"+wantLabel {
		t.Errorf("ptpTips(%v)=%q want %q", series, got, "absent|"+wantLabel)
	}
}

func TestOverallPoolUtil(t *testing.T) {
	cases := []struct {
		pools []views.PoolRow
		want  int
	}{
		{nil, 0},
		{[]views.PoolRow{{Allocated: 5, Capacity: 10}}, 50},
		{[]views.PoolRow{{Allocated: 0, Capacity: 0}}, 0},     // no capacity -> 0, no div-by-zero
		{[]views.PoolRow{{Allocated: 30, Capacity: 10}}, 100}, // elastic >100% clamped
		{[]views.PoolRow{{Allocated: 3, Capacity: 10}, {Allocated: 7, Capacity: 10}}, 50},
	}
	for _, c := range cases {
		if got := overallPoolUtil(c.pools); got != c.want {
			t.Errorf("overallPoolUtil(%v)=%d want %d", c.pools, got, c.want)
		}
	}
}

func TestBroadcastOf(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.1.50/24")
	b, ok := broadcastOf(ipnet)
	if !ok || b != [4]byte{192, 168, 1, 255} {
		t.Errorf("broadcastOf(/24)=%v,%v want 192.168.1.255", b, ok)
	}
	_, ipnet30, _ := net.ParseCIDR("10.0.0.4/30")
	b, ok = broadcastOf(ipnet30)
	if !ok || b != [4]byte{10, 0, 0, 7} {
		t.Errorf("broadcastOf(/30)=%v,%v want 10.0.0.7", b, ok)
	}
	// IPv6 must report not-ok rather than producing a bogus [4]byte.
	_, ipnet6, _ := net.ParseCIDR("fe80::/64")
	if _, ok := broadcastOf(ipnet6); ok {
		t.Error("broadcastOf(IPv6) should be not-ok")
	}
}

func TestNamesFromDevices(t *testing.T) {
	if namesFromDevices(nil) != nil {
		t.Error("empty input should return nil map")
	}
	devs := []ggoscan.Device{
		{MAC: "00:1f:80:12:34:56", Name: "Beltpack 1"},
		{MAC: "00:1f:80:aa:bb:cc", Name: ""}, // unnamed -> skipped
	}
	m := namesFromDevices(devs)
	if m[normalizeMAC("00:1f:80:12:34:56")] != "Beltpack 1" {
		t.Errorf("named device missing: %v", m)
	}
	if _, ok := m[normalizeMAC("00:1f:80:aa:bb:cc")]; ok {
		t.Error("unnamed device should be skipped")
	}
}

func TestFormReturn(t *testing.T) {
	// Same-site redirect guard: "/path" allowed, "//evil" and absolute URLs rejected.
	cases := []struct {
		ret  string
		want string
	}{
		{"/pinning", "/pinning"},
		{"//evil.com", "/dashboard"},          // protocol-relative -> rejected
		{"https://evil.com", "/dashboard"},    // absolute -> rejected
		{"", "/dashboard"},                    // missing -> default
		{"javascript:alert(1)", "/dashboard"}, // no leading slash -> rejected
	}
	for _, c := range cases {
		r := formRequest(url.Values{"return": {c.ret}})
		if got := formReturn(r, "/dashboard"); got != c.want {
			t.Errorf("formReturn(%q)=%q want %q", c.ret, got, c.want)
		}
	}
}

func TestJoinInts(t *testing.T) {
	cases := []struct {
		in   []int
		want string
	}{
		{nil, ""},
		{[]int{1}, "1"},
		{[]int{1, 200}, "1, 200"},
	}
	for _, c := range cases {
		if got := joinInts(c.in); got != c.want {
			t.Errorf("joinInts(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestParseUplinkForm(t *testing.T) {
	// Disabled: blank SSID is fine.
	cfg, err := parseUplinkForm(formRequest(url.Values{"uplink_enabled": {"off"}}))
	if err != nil || cfg.Enabled {
		t.Errorf("disabled uplink: cfg=%+v err=%v", cfg, err)
	}

	// Enabled without SSID must error.
	if _, err := parseUplinkForm(formRequest(url.Values{"uplink_enabled": {"on"}})); err == nil {
		t.Error("enabled uplink with no SSID should error")
	}

	// Enabled with valid SSID + password.
	cfg, err = parseUplinkForm(formRequest(url.Values{
		"uplink_enabled": {"on"}, "uplink_ssid": {"  NetA  "}, "uplink_pass": {"secret12"},
	}))
	if err != nil {
		t.Fatalf("valid uplink errored: %v", err)
	}
	if !cfg.Enabled || cfg.SSID != "NetA" || cfg.Password != "secret12" {
		t.Errorf("parsed uplink = %+v (SSID should be trimmed)", cfg)
	}

	// Enabled with a too-short password must error (WPA2 8-63).
	if _, err := parseUplinkForm(formRequest(url.Values{
		"uplink_enabled": {"on"}, "uplink_ssid": {"NetA"}, "uplink_pass": {"short"},
	})); err == nil {
		t.Error("too-short WPA2 password should error")
	}
}
