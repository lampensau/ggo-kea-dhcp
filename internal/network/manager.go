package network

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Manager owns interface, WiFi, SoftAP, and firewall configuration. All host
// access goes through its Commander, so it is fully unit-testable with a fake.
type Manager struct {
	cmd Commander
}

// NewManager returns a Manager that runs real privileged commands.
func NewManager() *Manager {
	return &Manager{cmd: NewSudoCommander()}
}

// NewManagerWithCommander returns a Manager backed by the given Commander
// (used by tests to inject a RecordingCommander).
func NewManagerWithCommander(c Commander) *Manager {
	return &Manager{cmd: c}
}

// RestartService restarts a systemd unit (sudo systemctl restart <name>) through
// the Commander seam. Used to recover Kea when its HTTP control socket is
// unreachable: a config-reload cannot bootstrap the :8004 listener, so only a
// restart - which makes Kea re-read its on-disk config - brings it back. No-ops in
// dev when systemctl is absent.
func (m *Manager) RestartService(name string) error {
	_, err := m.cmd.Run("systemctl", "restart", name)
	return err
}

// Reboot reboots the host (sudo systemctl reboot) through the Commander seam.
// The box goes down shortly after the command is issued; callers flush their HTTP
// response first. No-ops in dev when systemctl is absent. `systemctl` is already
// whitelisted in the sudoers drop-in, so no packaging change is needed.
func (m *Manager) Reboot() error {
	_, err := m.cmd.Run("systemctl", "reboot")
	return err
}

// PowerOff powers the host off (sudo systemctl poweroff). Same flush-first
// contract as Reboot; the box stays off until physically power-cycled.
func (m *Manager) PowerOff() error {
	_, err := m.cmd.Run("systemctl", "poweroff")
	return err
}

// SetInterfaceStatic configures an ethernet interface to manual mode with a static IP.
func (m *Manager) SetInterfaceStatic(iface, ipNet string) error {
	conName := fmt.Sprintf("ggo-%s", iface)
	log.Printf("Configuring interface %s static (%s) via NM...", iface, ipNet)

	// Delete existing connection if it exists to avoid conflicts
	_, _ = m.cmd.Run("nmcli", "connection", "delete", conName)

	if _, err := m.cmd.Run("nmcli", "connection", "add",
		"type", "ethernet",
		"con-name", conName,
		"ifname", iface,
		"ip4", ipNet,
		"ipv6.method", "disabled",
	); err != nil {
		return fmt.Errorf("failed to add static connection: %w", err)
	}

	if _, err := m.cmd.Run("nmcli", "connection", "up", conName); err != nil {
		return fmt.Errorf("failed to bring up connection: %w", err)
	}
	return nil
}

// SetVlanStatic configures a tagged VLAN interface on a parent ethernet port.
func (m *Manager) SetVlanStatic(parent string, vlanID int, ipNet string) error {
	iface := fmt.Sprintf("%s.%d", parent, vlanID)
	conName := fmt.Sprintf("ggo-%s", iface)
	log.Printf("Configuring VLAN interface %s (Parent: %s, Tag: %d) static (%s) via NM...", iface, parent, vlanID, ipNet)

	_, _ = m.cmd.Run("nmcli", "connection", "delete", conName)

	if _, err := m.cmd.Run("nmcli", "connection", "add",
		"type", "vlan",
		"con-name", conName,
		"ifname", iface,
		"dev", parent,
		"id", fmt.Sprintf("%d", vlanID),
		"ip4", ipNet,
		"ipv6.method", "disabled",
	); err != nil {
		return fmt.Errorf("failed to add VLAN connection: %w", err)
	}

	if _, err := m.cmd.Run("nmcli", "connection", "up", conName); err != nil {
		return fmt.Errorf("failed to bring up VLAN connection: %w", err)
	}
	return nil
}

// DeleteApplianceConnections removes all NM connections starting with "ggo-".
func (m *Manager) DeleteApplianceConnections() error {
	log.Println("Tearing down all ggo-kea-dhcp created NM connections...")

	output, err := m.cmd.Run("nmcli", "connection", "show", "--active")
	if err != nil {
		return err
	}

	// Columns: NAME, UUID, TYPE, DEVICE - the connection name is at the start.
	for line := range strings.SplitSeq(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) > 0 && strings.HasPrefix(parts[0], "ggo-") {
			conName := parts[0]
			log.Printf("Deleting connection %s...", conName)
			_, _ = m.cmd.Run("nmcli", "connection", "down", conName)
			_, _ = m.cmd.Run("nmcli", "connection", "delete", conName)
		}
	}
	return nil
}

// SetInterfaceManaged toggles whether NM controls a device.
func (m *Manager) SetInterfaceManaged(iface string, managed bool) error {
	state := "yes"
	if !managed {
		state = "no"
	}
	log.Printf("Setting NM device %s managed to %s...", iface, state)
	_, err := m.cmd.Run("nmcli", "device", "set", iface, "managed", state)
	return err
}

// SetWifiUplink configures wlan0 to connect to a WiFi access point. It retries up
// to 3 times with a delay to let NetworkManager detect the SSID after interface
// management changes.
func (m *Manager) SetWifiUplink(ssid, password string) error {
	const conName = "ggo-wifi-uplink"
	log.Printf("Connecting to WiFi uplink SSID '%s'...", ssid)

	_, _ = m.cmd.Run("nmcli", "connection", "delete", conName)

	args := []string{"device", "wifi", "connect", ssid}
	if password != "" {
		args = append(args, "password", password)
	}
	args = append(args, "name", conName)

	// Give NetworkManager a moment to initialize the interface after it is set to
	// managed, then prime the scan cache (wlan0 was just made managed).
	time.Sleep(2 * time.Second)
	log.Println("Triggering initial WiFi rescan...")
	_, _ = m.cmd.Run("nmcli", "device", "wifi", "rescan")
	time.Sleep(4 * time.Second)

	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		log.Printf("WiFi uplink connection attempt %d/3...", attempt)
		if _, err = m.cmd.Run("nmcli", args...); err == nil {
			log.Printf("Successfully connected to WiFi uplink SSID '%s'", ssid)
			return nil
		}
		log.Printf("WiFi uplink connection attempt %d/3 failed: %v", attempt, err)
		if attempt < 3 {
			log.Println("Triggering WiFi rescan and waiting for cache update...")
			_, _ = m.cmd.Run("nmcli", "device", "wifi", "rescan")
			time.Sleep(5 * time.Second)
		}
	}
	// The per-attempt log above keeps nmcli's raw text for diagnostics; the operator
	// only needs one plain sentence about which input to fix (the raw output names
	// device/secret internals and can run to many lines).
	return errors.New(wifiFailureReason(err))
}

// wifiFailureReason condenses nmcli's verbose connect failure into one
// operator-facing sentence. It informs about the problem; it never tells the
// operator to run a shell command.
func wifiFailureReason(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "no network with ssid"), strings.Contains(s, "ssid not found"):
		return "network not found - check the network name (SSID)"
	case strings.Contains(s, "secrets were required"), strings.Contains(s, "no secrets"),
		strings.Contains(s, "wireless-security"), strings.Contains(s, "psk"):
		return "the password was rejected - check the Wi-Fi password"
	case strings.Contains(s, "timeout"):
		return "the network did not respond - it may be out of range, or the password is wrong"
	default:
		return "could not connect - check the network name and password"
	}
}

// DisconnectWifiUplink removes the ggo-wifi-uplink NM connection.
func (m *Manager) DisconnectWifiUplink() error {
	_, err := m.cmd.Run("nmcli", "connection", "delete", "ggo-wifi-uplink")
	return err
}

// IsWifiUplinkActive reports whether the ggo-wifi-uplink NM connection is
// genuinely connected (STATE == "activated"), so the reconciler can skip the slow
// (re)connect. Crucially it does NOT count a profile that merely exists or is still
// "activating" - NetworkManager lists a saved autoconnect profile in --active the
// moment it starts trying, and keeps it there while an association/auth retry
// churns. Treating that as "up" is what let a boot whose saved profile never
// actually associated skip the explicit connect silently: no attempt, so no
// success and no error ever reached the log. Requiring "activated" makes the
// reconciler fall through and run SetWifiUplink (which retries and surfaces the
// real failure reason) whenever the link is not truly established.
func (m *Manager) IsWifiUplinkActive() bool {
	out, err := m.cmd.Run("nmcli", "-t", "-f", "NAME,STATE", "connection", "show", "--active")
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(out, "\n") {
		name, state, found := strings.Cut(strings.TrimSpace(line), ":")
		if found && name == "ggo-wifi-uplink" && state == "activated" {
			return true
		}
	}
	return false
}

// LinkStatus holds the link/trunk state of an interface.
type LinkStatus struct {
	ShieldState string // "Active", "Suspended"
	LinkState   string // "Flat", "Trunk", "Disconnected"
	Interface   string // e.g., "eth0"
}

// GetLinkStatus queries the link layer and trunk state of the target interface
// from sysfs (no privileged command needed).
func (m *Manager) GetLinkStatus(iface string) LinkStatus {
	carrierPath := filepath.Join("/sys/class/net", iface, "carrier")
	data, err := os.ReadFile(carrierPath)
	if err != nil {
		// In development fallback, return a simulated link.
		if _, statErr := os.Stat("/sys/class/net/" + iface); statErr != nil {
			return LinkStatus{ShieldState: "Active", LinkState: "Flat", Interface: iface}
		}
		return LinkStatus{ShieldState: "Suspended", LinkState: "Disconnected", Interface: iface}
	}

	if strings.TrimSpace(string(data)) != "1" {
		return LinkStatus{ShieldState: "Suspended", LinkState: "Disconnected", Interface: iface}
	}

	// Detect any active VLAN sub-interfaces (e.g. eth0.*) → trunk.
	files, gerr := filepath.Glob("/sys/class/net/" + iface + ".*")
	linkState := "Flat"
	if gerr == nil && len(files) > 0 {
		linkState = "Trunk"
	}
	return LinkStatus{ShieldState: "Active", LinkState: linkState, Interface: iface}
}

type WifiAP struct {
	SSID     string `json:"ssid"`
	Signal   int    `json:"signal"`
	Security string `json:"security"`
}

// dbmToQuality converts a dBm signal level to a 0-100 quality percentage.
func dbmToQuality(dbm int) int {
	return max(0, min(100, 2*(dbm+100)))
}

// wifiScanParser shares the AP-accumulation state machine (currentAP lifecycle +
// SSID dedup) across the per-tool scan formats; callers supply only the
// format-specific "is this a new AP?" predicate and the field extractor.
type wifiScanParser struct {
	isNewAP func(line string) bool
	apply   func(ap *WifiAP, line string)
}

func (p wifiScanParser) parse(out string) []WifiAP {
	var aps []WifiAP
	var cur *WifiAP
	seen := make(map[string]bool)
	flush := func() {
		if cur != nil && cur.SSID != "" && !seen[cur.SSID] {
			aps = append(aps, *cur)
			seen[cur.SSID] = true
		}
	}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if p.isNewAP(line) {
			flush()
			cur = &WifiAP{Security: "Open"}
			continue
		}
		if cur == nil {
			continue
		}
		p.apply(cur, line)
	}
	flush()
	return aps
}

// parseIwScan parses the output of `iw dev wlan0 scan`.
func parseIwScan(out string) []WifiAP {
	return wifiScanParser{
		isNewAP: func(l string) bool { return strings.HasPrefix(l, "BSS ") },
		apply: func(ap *WifiAP, l string) {
			switch {
			case strings.HasPrefix(l, "SSID:"):
				ap.SSID = strings.TrimSpace(strings.TrimPrefix(l, "SSID:"))
			case strings.HasPrefix(l, "signal:"):
				if parts := strings.Fields(l); len(parts) >= 2 {
					var dbm float64
					if _, err := fmt.Sscanf(parts[1], "%f", &dbm); err == nil {
						ap.Signal = dbmToQuality(int(dbm))
					}
				}
			case strings.Contains(l, "RSN:"), strings.Contains(l, "WPA:"), strings.Contains(l, "WPA2:"):
				ap.Security = "WPA2/WPA3"
			}
		},
	}.parse(out)
}

// parseIwlistScan parses the output of `iwlist wlan0 scan`.
func parseIwlistScan(out string) []WifiAP {
	return wifiScanParser{
		isNewAP: func(l string) bool { return strings.Contains(l, "Cell ") },
		apply: func(ap *WifiAP, l string) {
			switch {
			case strings.HasPrefix(l, "ESSID:"):
				ap.SSID = strings.Trim(strings.TrimPrefix(l, "ESSID:"), "\"")
			case strings.Contains(l, "Signal level="):
				parts := strings.Split(l, "Signal level=")
				if len(parts) >= 2 {
					var dbm int
					if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &dbm); err == nil {
						if dbm < 0 {
							ap.Signal = dbmToQuality(dbm)
						} else {
							ap.Signal = dbm // already a quality percentage
						}
					}
				}
			case strings.Contains(l, "WPA2"), strings.Contains(l, "WPA3"), strings.Contains(l, "IEEE 802.11i"):
				ap.Security = "WPA2/WPA3"
			}
		},
	}.parse(out)
}

// splitNmcliTerse splits one line of nmcli --terse output on field-separator colons,
// honoring nmcli's backslash escaping (`\:` is a literal colon inside a field, `\\` a
// literal backslash) so an SSID containing a colon parses into the right field.
func splitNmcliTerse(line string) []string {
	var fields []string
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && i+1 < len(line):
			i++
			b.WriteByte(line[i])
		case c == ':':
			fields = append(fields, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	return append(fields, b.String())
}

// parseNmcliScan parses the output of nmcli wifi list (SSID:SIGNAL:SECURITY).
func parseNmcliScan(out string, seen map[string]bool) []WifiAP {
	var aps []WifiAP
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := splitNmcliTerse(line)
		if len(parts) >= 3 {
			ssid := parts[0]
			if ssid == "" || seen[ssid] {
				continue
			}
			seen[ssid] = true
			signalVal := 0
			_, _ = fmt.Sscanf(parts[1], "%d", &signalVal) // unparseable signal -> 0, intended default
			aps = append(aps, WifiAP{SSID: ssid, Signal: signalVal, Security: parts[2]})
		}
	}
	return aps
}

// ScanWifi queries available wireless networks via iw, iwlist, or nmcli in turn.
func (m *Manager) ScanWifi() ([]WifiAP, error) {
	// If wlan0 doesn't physically exist, return mock data for development.
	if _, err := os.Stat("/sys/class/net/wlan0"); err != nil {
		log.Println("[Dev Mode] Bypassing wlan0 WiFi scan, returning mock APs")
		return []WifiAP{
			{SSID: "Venue-Production-WiFi", Signal: 95, Security: "WPA2"},
			{SSID: "Venue-Guest-WiFi", Signal: 78, Security: "WPA2"},
			{SSID: "Stage-Comms-Backplane", Signal: 92, Security: "WPA2 WPA3"},
		}, nil
	}

	var lastErr error
	sortBySignal := func(aps []WifiAP) {
		sort.Slice(aps, func(i, j int) bool { return aps[i].Signal > aps[j].Signal })
	}

	if out, err := m.cmd.Run("iw", "dev", "wlan0", "scan"); err == nil {
		if aps := parseIwScan(out); len(aps) > 0 {
			sortBySignal(aps)
			return aps, nil
		}
	} else {
		lastErr = err
		log.Printf("WiFi scanning via iw failed: %v", err)
	}

	if out, err := m.cmd.Run("iwlist", "wlan0", "scan"); err == nil {
		if aps := parseIwlistScan(out); len(aps) > 0 {
			sortBySignal(aps)
			return aps, nil
		}
	} else {
		lastErr = err
		log.Printf("WiFi scanning via iwlist failed: %v", err)
	}

	_, _ = m.cmd.Run("nmcli", "device", "wifi", "rescan")
	if out, err := m.cmd.Run("nmcli", "--terse", "--fields", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"); err == nil {
		if aps := parseNmcliScan(out, make(map[string]bool)); len(aps) > 0 {
			sortBySignal(aps)
			return aps, nil
		}
	} else {
		lastErr = err
		log.Printf("WiFi scanning via nmcli failed: %v", err)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all WiFi scanning backends failed. Last error: %w", lastErr)
	}
	return nil, fmt.Errorf("all WiFi scanning backends completed but returned no results")
}
