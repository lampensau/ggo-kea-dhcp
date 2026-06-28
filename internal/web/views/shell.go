package views

// link is a single primary-nav destination with its Lucide icon.
type link struct {
	Label string
	Path  string
	Icon  string
}

// navLinksFor returns the primary-nav links permitted in a lifecycle state. The
// server is the source of truth for which links exist; aria-current is set by
// matching the request path (see navLink). Sign-out is appended separately.
func navLinksFor(state string) []link {
	switch state {
	case "ACTIVE", "CONFIGURING":
		return []link{
			// Diagnostics absorbed the Audit Log; Settings absorbed Reset (its danger
			// zone), so those two are no longer separate nav tabs (/audit and /reset
			// redirect to their new homes).
			{"Dashboard", "/dashboard", "layout-dashboard"},
			{"DHCP Pools", "/pools", "layers"},
			{"Leases", "/leases", "network"},
			{"Port Pinning", "/pinning", "pin"},
			{"Diagnostics", "/diagnostics", "activity"},
			{"Settings", "/settings", "settings"},
		}
	case "ONBOARDING":
		// Onboarding is the wizard only - Settings (onboarding IP / SoftAP /
		// password) is reachable at /settings if needed but not a nav tab here,
		// to keep the first-run flow focused on applying a profile.
		return []link{
			{"Setup Wizard", "/setup", "server"},
		}
	default:
		return nil
	}
}

// pillHref points the header status pill at Diagnostics, deep-linking to the latest live
// alert (#latest-alert, resolved by auditJumpScript) when a warning/error is active so a
// click jumps straight to the relevant audit entry; otherwise the page top.
func pillHref(v StatusPillView) string {
	if v.ErrCount > 0 || v.WarnCount > 0 {
		return "/diagnostics#latest-alert"
	}
	return "/diagnostics"
}

// hasNav reports whether the two-tier header should render its nav row.
func hasNav(d PageData) bool {
	return d.Authenticated && len(navLinksFor(d.State)) > 0
}

// statusPillClass maps a lifecycle state to the header status-pill variant:
// ACTIVE = ok (green), CONFIGURING = info (accent), ONBOARDING/FACTORY = warn.
func statusPillClass(state string) string {
	switch state {
	case "ACTIVE":
		return "is-ok"
	case "CONFIGURING":
		return "is-info"
	case "FACTORY", "ONBOARDING":
		return "is-warn"
	default:
		return ""
	}
}

// statusLabel is the human-readable lifecycle label shown in the status pill.
func statusLabel(state string) string {
	switch state {
	case "ACTIVE":
		return "Active"
	case "CONFIGURING":
		return "Configuring"
	case "ONBOARDING":
		return "Onboarding"
	case "FACTORY":
		return "Factory"
	default:
		return state
	}
}

// pageHealthPill returns the page's health pill, defaulting its State to the page's
// lifecycle State when the caller didn't populate the aggregated pill (e.g. a
// hand-built PageData in a test, or a render path that skips the alert aggregation).
func pageHealthPill(d PageData) StatusPillView {
	p := d.HealthPill
	if p.State == "" {
		p.State = d.State
	}
	return p
}

// pillHealthClass colors the header pill by the worst live alert (err > warn),
// falling back to the lifecycle-state color when the network is clean.
func pillHealthClass(v StatusPillView) string {
	switch {
	case v.ErrCount > 0:
		return "is-err"
	case v.WarnCount > 0:
		return "is-warn"
	default:
		return statusPillClass(v.State)
	}
}

// pillLabel is the lifecycle label plus a "· N errors/warnings" counter (errors take
// precedence). A clean network shows just the state label.
func pillLabel(v StatusPillView) string {
	switch {
	case v.ErrCount > 0:
		return statusLabel(v.State) + " · " + itoa(v.ErrCount) + " " + pluralize(v.ErrCount, "error", "errors")
	case v.WarnCount > 0:
		return statusLabel(v.State) + " · " + itoa(v.WarnCount) + " " + pluralize(v.WarnCount, "warning", "warnings")
	default:
		return statusLabel(v.State)
	}
}

// pillTitle is the pill's hover tooltip: the state explanation, then each live alert
// title on its own line (newlines render in a native title attribute).
func pillTitle(v StatusPillView) string {
	t := statusPillTitle(v.State)
	for _, d := range v.Details {
		t += "\n• " + d
	}
	return t
}

// statusPillTitle is the hover/aria explanation of what the lifecycle state means -
// the label alone ("Active") doesn't say what is active.
func statusPillTitle(state string) string {
	switch state {
	case "ACTIVE":
		return "Profile applied; DHCP is serving addresses."
	case "CONFIGURING":
		return "Applying a profile; DHCP is reloading."
	case "ONBOARDING":
		return "No profile yet - finish setup to start DHCP."
	case "FACTORY":
		return "Create an admin account to begin."
	default:
		return state
	}
}
