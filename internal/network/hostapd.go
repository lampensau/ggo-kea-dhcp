package network

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// validateSoftAP rejects values that would corrupt the line-oriented
// hostapd.conf (a newline in ssid/passphrase injects arbitrary directives) or
// violate WPA2 constraints. It is the boundary check for the reconciler, which
// feeds StartSoftAP values straight from app_state.
func validateSoftAP(ssid, passphrase string) error {
	if ssid == "" {
		return fmt.Errorf("softap ssid must not be empty")
	}
	if len(ssid) > 32 {
		return fmt.Errorf("softap ssid must be at most 32 bytes")
	}
	if hasControlChar(ssid) {
		return fmt.Errorf("softap ssid must not contain control characters")
	}
	if passphrase != "" {
		if len(passphrase) < 8 || len(passphrase) > 63 {
			return fmt.Errorf("softap passphrase must be 8-63 characters (WPA2)")
		}
		if hasControlChar(passphrase) {
			return fmt.Errorf("softap passphrase must not contain control characters")
		}
	}
	return nil
}

func hasControlChar(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// softAPConfPath is where the generated hostapd.conf is written (/tmp because the
// service user can't write /etc/kea).
const softAPConfPath = "/tmp/hostapd.conf"

// StartSoftAP configures and launches hostapd on wlan0.
func (m *Manager) StartSoftAP(ssid, passphrase string) error {
	log.Printf("Starting SoftAP (SSID: '%s')...", ssid)

	if err := validateSoftAP(ssid, passphrase); err != nil {
		return err
	}

	// hostapd config (open/unprotected when passphrase is empty).
	var confContent string
	if passphrase == "" {
		confContent = fmt.Sprintf("interface=wlan0\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=6\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\n", ssid)
	} else {
		confContent = fmt.Sprintf("interface=wlan0\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=6\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\nwpa=2\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n", ssid, passphrase)
	}
	if err := os.WriteFile(softAPConfPath, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("failed to write hostapd config: %w", err)
	}

	// Ensure no other hostapd is running first.
	_ = m.StopSoftAP()

	// Clear any pre-existing IPv4 on wlan0 (e.g. a leftover WiFi-uplink address from a
	// prior ACTIVE state) so the interface carries ONLY the SoftAP IP. Otherwise wlan0 is
	// dual-homed and Kea - reloaded moments later against that interface - binds stale
	// sockets and silently never answers the SoftAP's DHCP. Mirror of StopSoftAP's flush;
	// the two together keep wlan0's role transitions clean.
	_, _ = m.cmd.Run("ip", "-4", "addr", "flush", "dev", "wlan0")

	// Assign a static IP to wlan0 and bring it up. These are best-effort (warn,
	// don't fail) - the Commander already no-ops when `ip` is absent in dev.
	if _, err := m.cmd.Run("ip", "addr", "replace", softAPWlanCIDR, "dev", "wlan0"); err != nil {
		log.Printf("Warning: failed to set IP on wlan0: %v", err)
	}
	if _, err := m.cmd.Run("ip", "link", "set", "wlan0", "up"); err != nil {
		log.Printf("Warning: failed to bring wlan0 up: %v", err)
	}

	// Start hostapd as a background daemon (-B). The Commander bypasses (no error)
	// when hostapd isn't installed, so this is a no-op in dev.
	if _, err := m.cmd.Run("hostapd", "-B", softAPConfPath); err != nil {
		return fmt.Errorf("failed to start hostapd: %w", err)
	}

	log.Println("SoftAP started successfully in background.")
	return nil
}

// softAPWlanCIDR is the address hostapd assigns to wlan0 in onboarding. It sits in
// the top corner of 172.16.0.0/12 - the least-used RFC 1918 range - deliberately
// away from the 10/8 and 192.168/16 ranges an operator subnet almost always uses,
// so even a stray leftover can't be swallowed by (and shadow) a larger operator
// subnet on eth0. Keep in sync with softAPWlanIP in internal/web/reconciler.go.
const softAPWlanCIDR = "172.31.255.1/24"

// StopSoftAP stops the running hostapd process and removes the SoftAP address
// from wlan0. Dropping the address is load-bearing: if it lingers after the box
// leaves onboarding, its on-link /24 route shadows an overlapping (larger) eth0
// operator subnet for any client in that /24, so the box's replies leave via the
// (now idle/uplink) wlan0 and are lost. `addr del` of the specific CIDR leaves a
// WiFi-uplink address on wlan0 untouched (unlike `addr flush`).
func (m *Manager) StopSoftAP() error {
	log.Println("Stopping SoftAP...")
	// Errors are expected (no process / no service / address absent) and ignored.
	_, _ = m.cmd.Run("pkill", "hostapd")
	_, _ = m.cmd.Run("systemctl", "stop", "hostapd")
	_, _ = m.cmd.Run("ip", "addr", "del", softAPWlanCIDR, "dev", "wlan0")
	return nil
}
