// Package views holds the templ-rendered UI components and their view models.
//
// It deliberately imports nothing from internal/web: the web package builds
// these plain view-model structs from its handler data and renders the
// components, so the dependency only ever points web -> views (no cycle).
//
// Rendering stack: templ (type-safe Go components) + Datastar (declarative
// data-* attributes for interaction and SSE-driven live updates). The same
// component renders both the initial full page and the SSE live-fragment, so
// first paint and live updates can never drift. See internal/web/DESIGN.md.
package views

// PageData is the shell context every full page needs: lifecycle state (for the
// header badge and nav), auth status, the session CSRF token (surfaced to
// Datastar actions), the current path (for aria-current nav highlighting), an
// optional one-shot flash, and the document title.
type PageData struct {
	State         string
	Authenticated bool
	Username      string
	CSRFToken     string
	CurrentPath   string
	Title         string
	Flash         *Flash
	// AssetVer is a content-hash appended to static asset URLs (?v=) so cache
	// busting happens automatically on a binary upgrade.
	AssetVer string
	// Version is the product version (internal/version.Number), shown in the global
	// fixed footer (appFooter) on every authenticated page.
	Version string
	// SysHealth is the header CPU/memory/storage indicator (rendered only when
	// authenticated and ACTIVE; SysHealthView.Show gates the actual content).
	SysHealth SysHealthView
	// HealthPill is the header status pill: the lifecycle state plus the live netmon
	// alert counts. It recolors to the worst severity and links to /audit. Backend
	// service health (Kea/MariaDB/uplink) is NOT folded in here - it gets the more
	// prominent BackendAlerts strip instead.
	HealthPill StatusPillView
	// BackendAlerts is the backend-health strip rendered above the page h1: Kea down
	// (error - DHCP stopped), MariaDB down / Wi-Fi uplink down (warnings). Empty when
	// every backend is healthy, so the #backend-alert:empty rule collapses it.
	BackendAlerts []AlertRow
}

// StatusPillView is the header status pill: the lifecycle State plus aggregated live
// alert counts. The pill recolors to the worst severity (err > warn > state), shows a
// "· N warnings/errors" suffix, lists the alert lines in its tooltip, and always links
// to the Audit Log. Details holds the short alert titles for the tooltip.
type StatusPillView struct {
	State     string
	WarnCount int
	ErrCount  int
	Details   []string
}

// Flash is a one-shot toast message surfaced from the flash cookie.
type Flash struct {
	Message string
	Type    string // "success" | "error" | "info"
}

// SysHealthView models the header system-health indicator: the worst-of CPU /
// memory / storage severity tints a CPU icon, with the three figures in a tooltip.
// Show is false (empty render) off-ACTIVE or before the sampler has a reading.
type SysHealthView struct {
	Show     bool
	Severity string // "ok" | "warn" | "err"
	CPU      int    // percent
	Mem      int    // percent
	Disk     int    // percent
}

// sysHealthAria is the accessible label / hover text for the indicator.
func sysHealthAria(v SysHealthView) string {
	return "System health - CPU " + itoa(v.CPU) + "%, memory " + itoa(v.Mem) + "%, storage " + itoa(v.Disk) + "%"
}

// LoginView is the model for the sign-in page.
type LoginView struct {
	Page  PageData
	Error string
}

// pageTitle composes the document <title>, defaulting when a page sets none.
func pageTitle(t string) string {
	if t == "" {
		return "Green-GO Kea DHCP Server"
	}
	return t + " · Green-GO Kea DHCP Server"
}
