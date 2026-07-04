package views

// --- Factory (admin bootstrap) ---

type FactoryView struct {
	Page  PageData
	Error string
}

// --- Settings ---

type SettingsView struct {
	Page         PageData
	OnboardingIP string
	SoftAPSSID   string
	SoftAPPass   string
	// Global DHCP option defaults (every scope inherits unless it overrides per-scope):
	// a default DNS resolver list and a free-form option list (ntp-servers, ...).
	GlobalDNS     string
	GlobalOptions []ScopeOptionRow
	// WiFi uplink (client) - editable only in ACTIVE, where wlan0 is in managed
	// mode (before that it hosts the onboarding SoftAP). ShowUplink gates the card.
	ShowUplink     bool
	UplinkEnabled  bool
	UplinkSSID     string
	UplinkPassword string
	// LeaseLifetime is the active-profile DHCP lease lifetime in seconds.
	LeaseLifetime int
	// Username is the current administrator's name (the rename field's value).
	Username string
}

// --- Setup wizard ---

type SetupView struct {
	Page        PageData
	ShieldState string // "Active" | suspended
	LinkState   string // "Disconnected" | "Trunk" | "Access"
	Interface   string
	LinkDetail  string // e.g. "tagged VLANs seen: 1, 200" - the Trunk badge tooltip
	Editing     bool   // true when reopened to edit the active profile (vs new)
	PrefillJSON string // active profile as wizard-import JSON when Editing
	// Box-level WiFi uplink (one wlan0), shown in the Profile card. Per-scope is just
	// a toggle; these credentials are box-wide.
	UplinkEnabled  bool
	UplinkSSID     string
	UplinkPassword string
}
