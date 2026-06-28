package web

// Input validators shared by the setup wizard and the settings page. These are
// defense-in-depth: privileged commands run via an args array (never a shell
// string), so these values are not injectable - but rejecting out-of-range VLAN
// ids and control characters early keeps malformed input out of nmcli/hostapd and
// the generated Kea config, and gives the operator a clear error.

// hasControlChar reports whether s contains an ASCII control character (< 0x20 or
// DEL). Control characters are invalid in an SSID/passphrase and would corrupt a
// generated config line, so they are rejected at input (parity with the SoftAP
// validation in internal/network/hostapd.go).
func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validVLANID reports whether v is a usable 802.1Q VLAN id for a served scope.
// 0 means the untagged scope on eth0 (already valid in this codebase); 1..4094 are
// taggable; 4095 is reserved and negative values are nonsense.
func validVLANID(v int) bool {
	return v >= 0 && v <= 4094
}

// validateUplink checks a WiFi uplink SSID/passphrase against the constraints nmcli
// and WPA2 impose, returning a user-facing message on the first violation (or ""
// when valid). Only meaningful for an enabled uplink; a disabled uplink carries no
// credentials. An empty password means an open network and is allowed.
func validateUplink(ssid, password string) string {
	if l := len(ssid); l < 1 || l > 32 {
		return "WiFi network name (SSID) must be 1-32 characters."
	}
	if hasControlChar(ssid) {
		return "WiFi network name (SSID) contains invalid control characters."
	}
	if password != "" {
		if l := len(password); l < 8 || l > 63 {
			return "WiFi password must be 8-63 characters (WPA2), or empty for an open network."
		}
		if hasControlChar(password) {
			return "WiFi password contains invalid control characters."
		}
	}
	return ""
}
