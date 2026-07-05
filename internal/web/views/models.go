package views

import (
	"strconv"
	"strings"
)

// vendorsField is the space-separated raw OUI list posted in the hidden vendors
// field (splitVendors parses it back); NOT the " · " display string.
func vendorsField(p PoolPlanRow) string { return strings.Join(p.VendorList, " ") }

// ppCustomVendor builds the @post for the custom-OUI Add button: it appends the
// $coui signal (the bound text input) to the add-vendor op value at click time.
func ppCustomVendor(v PoolPlanView, idx int) string {
	if v.EditAction == "" {
		return ""
	}
	q := v.EditAction + "?s=" + itoa(v.Scope) + "&op=add-custom-oui&mode=" + v.Mode + "&i=" + itoa(idx) + "&v="
	return "@post('" + q + "' + $coui1 + $coui2 + $coui3, {contentType:'form'})"
}

// itoa renders an int for templ interpolation.
func itoa(n int) string { return strconv.Itoa(n) }

// itoa64 renders an int64 (the absolute lease-expiry epoch) for templ interpolation.
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// attrBool renders a Go bool as the literal "true"/"false" for an ARIA attribute
// (aria-pressed etc., which are enumerated strings, not boolean-presence attributes).
func attrBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// setupSignals seeds the wizard form's Datastar signals (the box-level WiFi-uplink
// enable reveal).
func setupSignals(v SetupView) string {
	return "{up: " + strconv.FormatBool(v.UplinkEnabled) + "}"
}

// settingsSignals is the initial Datastar signal set for the settings form
// (the WiFi-uplink-enabled toggle).
func settingsSignals(v SettingsView) string {
	return "{uplink: " + strconv.FormatBool(v.UplinkEnabled) + "}"
}

// orDash shows an em dash for empty optional fields (hostname, etc.).
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// pluralize picks the singular or plural noun for a count.
func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// releaseExpr builds the Datastar @delete expression for the lease release
// button: a native confirm gates the delete, which carries the CSRF header. ip
// is an IPv4 string. The CSRF token is read dynamically from the DOM (not passed
// in) so the live ticker can rebroadcast the row without a session CSRF token.
func releaseExpr(ip string) string {
	return "confirm('Release lease for " + ip + "?') && @delete('/leases/release?ip=" + ip +
		"', {headers: {'X-CSRF-Token': document.querySelector('meta[name=\"csrf-token\"]').content}})"
}

// Page view models. These are plain data the web handlers populate; the views
// package never imports web. Row types are defined here (not in web) so handlers
// build them directly and there's a single source of truth for display shape.
