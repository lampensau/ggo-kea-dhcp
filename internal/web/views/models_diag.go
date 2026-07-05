package views

import (
	"strconv"
	"strings"
)

// --- Audit ---

// AuditRow is one audit-log entry. Before/After carry the stored context (e.g. an LLDP
// neighbor label, a backend-health detail) that the expandable Diagnostics rows surface.
// ID is the audit_log primary key, used as the row's scroll anchor (id="audit-<ID>").
type AuditRow struct {
	ID        int
	Timestamp string
	Actor     string
	Action    string
	Target    string
	Before    string
	After     string
	Result    string
}

// --- Diagnostics ---

// DiagnosticsView models the Diagnostics page: the prerequisite checks, an optional
// database-recovery notice, and the recent system/audit events (folded in from the
// former Audit Log page). Degraded is true when any check is WARN/FAIL - it auto-opens
// the otherwise-collapsed checks card.
type DiagnosticsView struct {
	Page     PageData
	Checks   []DiagRow
	Degraded bool
	Recovery *DiagRecovery
	Logs     []AuditRow
}

// diagIssues counts the WARN and FAIL checks, for the collapsed checks-card summary.
func diagIssues(checks []DiagRow) (warn, fail int) {
	for _, c := range checks {
		switch c.Status {
		case "OK":
		case "WARN":
			warn++
		default:
			fail++
		}
	}
	return
}

// DiagRow is one prerequisite check result (mirrors preflight.Check, mapped in the
// handler so the views package stays independent of the preflight package).
type DiagRow struct {
	Status string // "OK" | "WARN" | "FAIL"
	Name   string
	Detail string
}

// DiagRecovery describes a control-plane database that was found corrupt at boot,
// moved aside, and recreated - shown so the operator knows to restore a backup.
type DiagRecovery struct {
	When string // human-readable recovery time
	From string // path the corrupt database was moved to
}

// auditResultLabel renders an audit result code as a readable, sentence-case
// label. Unknown codes fall through verbatim so nothing is hidden.
func auditResultLabel(result string) string {
	switch result {
	case "SUCCESS":
		return "Success"
	case "OK":
		return "OK"
	case "WARNING", "WARN":
		return "Warning"
	case "INFO":
		return "Info"
	case "ERROR":
		return "Error"
	case "FAIL", "FAILED":
		return "Failed"
	default:
		return result
	}
}

// auditActionLabels maps the raw audit action tokens (the second arg to LogAudit) to
// human-readable labels for the audit log + dashboard activity feed.
var auditActionLabels = map[string]string{
	"APPLY_PROFILE":      "Profile applied",
	"SWITCH_PROFILE":     "Profile switched",
	"DELETE_PROFILE":     "Profile deleted",
	"LEASE_REBALANCE":    "Lease rebalance",
	"LEASE_RELEASE":      "Lease released",
	"PIN_PORT":           "Port pinned",
	"UNPIN_PORT":         "Port unpinned",
	"LABEL_PORT":         "Port labeled",
	"RESERVATION_ADD":    "Reservation added",
	"RESERVATION_DELETE": "Reservation removed",
	"EDIT_POOLS":         "Pools edited",
	"UPDATE_SETTINGS":    "Settings updated",
	"UPDATE_UPLINK":      "Uplink updated",
	"UPLINK_UP":          "Uplink up",
	"UPLINK_DOWN":        "Uplink down",
	"CHANGE_PASSWORD":    "Password changed",
	"INITIALIZE_ADMIN":   "Administrator created",
	"RESET_ONBOARDING":   "Reset to onboarding",
	"BACKUP_EXPORT":      "Backup exported",
	"BACKUP_RESTORE":     "Backup restored",
	"LOGIN":              "Signed in",
	"LOGOUT":             "Signed out",
	"LOGIN_THROTTLE":     "Login throttled",
	"SYSTEM":             "System",
}

// auditActionLabel renders a raw audit action token (e.g. "LEASE_REBALANCE") as a
// readable label. An unknown token falls back to a Title-cased form ("FOO_BAR" -> "Foo
// bar") so a newly-added action still reads sanely without a map entry.
func auditActionLabel(action string) string {
	if lbl, ok := auditActionLabels[action]; ok {
		return lbl
	}
	// Only humanize SCREAMING_SNAKE tokens. An action that already contains a space or any
	// lowercase letter is a human string (e.g. netmon events like "Static device in DHCP
	// pool") - return it verbatim so acronyms (DHCP, PTP, IGMP, sACN) survive.
	if strings.ContainsRune(action, ' ') || strings.ToUpper(action) != action {
		return action
	}
	s := strings.ToLower(strings.ReplaceAll(action, "_", " "))
	if s == "" {
		return action
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// auditSummary is the one-line detail shown in the collapsed audit row (the cell
// truncates with ellipsis). It favors the stored After context (the rich part of a
// netmon/system event), falling back to the target.
func auditSummary(r AuditRow) string {
	// The firmware entry's After is the full device roster - expanded-view context.
	// The collapsed cell shows only the compact census (Target), so the two never
	// mirror each other and the column can't overflow.
	if r.Action == "Mixed Green-GO firmware" {
		return orDash(r.Target)
	}
	a := afterDetail(r.After)
	if a == "" {
		return orDash(r.Target)
	}
	if r.Target != "" && r.Target != "0.0.0.0" {
		return a + " · " + r.Target
	}
	return a
}

// afterDetail returns the After value when it carries standalone meaning, else "".
// State-token transitions (none/absent/ok/gone/static/link-local) and bare counts are
// noise on their own, so they collapse to "".
func afterDetail(after string) string {
	switch strings.ToLower(strings.TrimSpace(after)) {
	case "", "none", "absent", "ok", "gone", "static", "link-local", "mixed", "uniform":
		return ""
	}
	if _, err := strconv.Atoi(strings.TrimSpace(after)); err == nil {
		return ""
	}
	return after
}

// auditExplain is the plain-language explanation shown when an audit row is expanded -
// the Diagnostics page is the verbose place, so a non-expert reads what an event means,
// not just its terse code. Known system/netmon and admin actions get a sentence; anything
// else composes a sane line from the action label, target, and stored after-detail.
func auditExplain(r AuditRow) string {
	switch r.Action {
	case "Switch neighbor seen":
		return "Upstream switch detected on " + r.Target + " via LLDP" + afterPhrase(r.After) + "."
	case "Switch neighbor lost":
		return "Upstream switch on " + r.Target + " stopped advertising (link down)."
	case "IGMP querier present":
		return "IGMP querier active on this segment (multicast routing present)."
	case "Startup":
		return "Control-plane service started."
	case "Mixed Green-GO firmware":
		s := "Green-GO devices are running different firmware releases (" + r.Target + ")."
		if r.After != "" {
			s += " Devices: " + r.After + "."
		}
		return s
	case "Green-GO firmware mismatch cleared":
		return "All Green-GO devices are back on a single firmware release."
	case "Evenution devices without DHCP lease":
		return "Green-GO devices are active on the network without a DHCP lease (address purged, wiped, or statically set): " + orDash(r.Target) + ". They renew automatically at their next DHCP request; reserve the address if it is intentionally static."
	case "Evenution no-lease warning cleared":
		return "Every active Green-GO device holds a DHCP lease again."
	}
	switch r.Action {
	case "APPLY_PROFILE":
		return "DHCP profile applied" + targetPhrase(r.Target) + "; Kea reloaded."
	case "SWITCH_PROFILE":
		return "Active DHCP profile switched" + targetPhrase(r.Target) + "; appliance re-IPed."
	case "EDIT_POOLS":
		return "Pool plan edited" + targetPhrase(r.Target) + "; Kea reloaded."
	case "PIN_PORT":
		return "Port pinned to a reservation: " + orDash(r.Target) + "."
	case "UNPIN_PORT":
		return "Port reservation removed: " + orDash(r.Target) + "."
	case "UPDATE_SETTINGS", "UPDATE_UPLINK":
		return "Settings changed by " + r.Actor + "."
	case "LOGIN":
		return r.Actor + " signed in."
	case "LOGOUT":
		return r.Actor + " signed out."
	case "BACKUP_EXPORT":
		return "Appliance backup downloaded by " + r.Actor + "."
	case "BACKUP_RESTORE":
		return "Appliance restored from a backup."
	}
	// Backend health (action is "<backend>_DOWN"/"_UP", detail in After).
	switch {
	case strings.HasSuffix(r.Action, "_DOWN"):
		return strings.TrimSuffix(r.Action, "_DOWN") + " stopped responding" + afterPhrase(r.After) + "."
	case strings.HasSuffix(r.Action, "_UP"):
		return strings.TrimSuffix(r.Action, "_UP") + " responding again" + afterPhrase(r.After) + "."
	}
	g := auditActionLabel(r.Action) + targetPhrase(r.Target)
	// Append the after-detail only when it adds something the action sentence doesn't
	// already say (netmon actions are full sentences, so "(link-local)" after "...on
	// link-local..." is noise).
	if p := afterPhrase(r.After); p != "" && !strings.Contains(strings.ToLower(r.Action), strings.ToLower(r.After)) {
		g += p
	}
	return g + "."
}

// afterPhrase renders a meaningful After value as " (<after>)", else "".
func afterPhrase(after string) string {
	if d := afterDetail(after); d != "" {
		return " (" + d + ")"
	}
	return ""
}

// targetPhrase renders a non-empty target as " for <target>".
func targetPhrase(target string) string {
	if target == "" {
		return ""
	}
	return " for " + target
}

// diagDot maps a check status to a status-dot variant.
func diagDot(status string) string {
	switch status {
	case "OK":
		return "ok"
	case "WARN":
		return "warn"
	default:
		return "err"
	}
}

// diagBadgeClass maps a check status to a badge variant.
func diagBadgeClass(status string) string {
	switch status {
	case "OK":
		return "badge-ok"
	case "WARN":
		return "badge-warn"
	default:
		return "badge-err"
	}
}
