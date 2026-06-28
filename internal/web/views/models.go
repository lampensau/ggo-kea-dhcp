package views

import (
	"strconv"
	"strings"

	"github.com/a-h/templ"
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
// (WiFi-uplink-enabled toggle, new-password match check, password-reveal toggle).
func settingsSignals(v SettingsView) string {
	return "{uplink: " + strconv.FormatBool(v.UplinkEnabled) + ", np: '', np2: '', showpw: false}"
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

// --- Dashboard ---

// DashboardView is the at-a-glance appliance view: a compact summary line, three
// tiles, and the address-pool table (#dash-tiles and #pool-table are the live
// regions the SSE ticker re-merges, rendered by the same partials as first paint).
type DashboardView struct {
	Page         PageData
	ProfileName  string
	Preset       string
	Interface    string
	TotalScopes  int
	LeaseCount   int
	UplinkActive bool
	Pools        []PoolRow
	Profiles     []ProfileOption
	NetHealth    NetHealthView
	Stats        []StatTileView // live stat tiles (#dash-tiles), with sparklines
	Activity     []AuditRow     // recent-activity feed (#activity-feed)
	RecentLeases []LeaseRow     // active-leases summary card (#recent-leases)
	Pinned       []PortRow      // configured port pinnings (#pinnings + #pinned-body)
	Learnable    []PortRow      // learnable ports (#learnable-body, /pinning page)
	LLDP         LLDPChip       // "you are here" chip in the config card
	PTP          []PTPRow       // PTP clock panel (#ptp-panel)
	CanReserve   bool           // MariaDB host store online → show the Reserve action
}

// auditDot maps an audit_log Result to a status-dot variant for the activity feed
// (errors red, warnings amber, OK green, info/other neutral).
func auditDot(result string) string {
	switch result {
	case "ERROR":
		return "err"
	case "WARNING":
		return "warn"
	case "OK":
		return "ok"
	default:
		return ""
	}
}

// ProfileOption is one saved profile in the dashboard's profile switcher.
type ProfileOption struct {
	ID         int
	Name       string
	Active     bool
	ScopeCount int
}

// hasOtherProfiles reports whether a non-active saved profile exists (so the
// dashboard only renders the switcher when there is somewhere to switch to).
func hasOtherProfiles(ps []ProfileOption) bool {
	for _, p := range ps {
		if !p.Active {
			return true
		}
	}
	return false
}

// PoolRow is one pool's occupancy. ClassName is the raw Kea client-class; Label
// is its operator-facing name (ClassDisplay). The pool table stays text-only.
type PoolRow struct {
	ClassName string
	Label     string
	IPRange   string
	Allocated int
	Capacity  int
	Percent   int
}

// PoolPlanRow is one pool in the wizard's one-view pool plan (the table that
// absorbs the old device-count grid). Each row carries its own number: a Count
// when Sized, a Weight when Elastic. Elastic vs Sized is per-pool, operator-set.
// Prefix is the fixed CIDR network part shown greyed in Advanced mode; Start/End
// are the editable host parts; Range is the full derived range shown in Simple.
type PoolPlanRow struct {
	Key              string   // identity / override key (Kea client-class, or "dynamic")
	Name             string   // editable operator-facing pool name
	Icon             string   // device-icon key (Green-GO silhouette or Lucide fallback)
	Codes            string   // device codes subtitle (e.g. "BPX / BP2"), optional
	Vendor           string   // joined classifier text ("" = built-in / unclassified catch-all)
	VendorList       []string // raw MAC-OUI prefixes (each a removable chip; posted as the field)
	Elastic          bool     // size policy: true = weighted remainder, false = sized
	Weight           int      // remainder weight when Elastic (≥1)
	Count            int      // forecast device count when Sized
	Floor            int      // minimum allowed count/size value
	Size             int      // derived capacity (addresses) for display
	Prefix           string   // fixed CIDR network part, e.g. "10.0.0." (Advanced)
	Start            string   // host-part start value, e.g. "235"
	End              string   // host-part end value, e.g. "244"
	StartPlaceholder string   // host-part start placeholder, e.g. "20"
	EndPlaceholder   string   // host-part end placeholder, e.g. "150"
	Range            string   // full derived range for DISPLAY, e.g. "10.0.0.20 - 10.0.0.150"
	// RangePin is the operator's EXPLICIT range pin (empty for an auto-derived
	// pool). Only this is posted back as the entry's range - never the computed
	// display Range, which would round-trip as a spurious pin and stop LayoutPools
	// from reflowing when a pool is added/removed/reordered.
	RangePin     string
	Err          bool // flagged: part of an unresolved overlap/bounds issue
	IconEditable bool // true for non-Green-GO pools (icon is a curated picker)
	Reserve      bool // carved-out empty space (label + range, not a DHCP pool)
	Locked       bool // can't be removed (the "Any unmatched device" safety net)
	// Live utilization (shown only when PoolPlanView.ShowUtil - i.e. on /pools,
	// where leases exist; the wizard omits it).
	Used     int
	Capacity int
	Percent  int
	// CountField, when set, is the form `name` for this row's count input so the
	// wizard's PoolPlan posts device counts as scopes[i][count_*] (empty elsewhere).
	CountField string
}

// PoolPlanView is the wizard scope card's pool plan in one of two live modes.
type PoolPlanView struct {
	Mode        string // "simple" | "advanced"
	Subnet      string // scope CIDR, e.g. "10.0.0.0/24"
	FreeIPs     int    // unallocated addresses left (free reserve)
	Gateway     string // gateway address, e.g. "10.0.0.1"
	Issue       string // unresolved overlap/bounds message (best-effort failed)
	ShowUtil    bool   // render the live Utilization column (/pools, not the wizard)
	Heading     string // head title; defaults to "Pool plan" when empty
	SizePresets bool   // render the S/M/L/Custom size tabs above the table (wizard)
	ActiveSize  string // which size tab is fused/active ("small"|"medium"|"large"|"custom")
	// Datastar editor wiring. RegionID is the morph target (e.g. "poolplan-0");
	// FieldPrefix names the entry form fields (e.g. "scopes[0][pool]"); EditAction
	// is the SSE op endpoint (e.g. "/setup/pools/edit"); Scope is this scope's index.
	// When EditAction is "" the plan renders read-only (no controls wired).
	RegionID    string
	FieldPrefix string
	EditAction  string
	// SaveAction, when set (the /pools page), renders a primary "Save changes"
	// button in the foot that posts the enclosing form to persist + reconcile.
	// The wizard leaves it empty - it saves through the big /setup/apply form.
	SaveAction string
	Scope      int
	// Greengo gates the Add-pool control: a greengo scope opens a menu of the known
	// Green-GO device classes (plus a Generic pool entry); any other preset keeps the
	// plain "Add pool" button (a single generic, OUI-routed pool).
	Greengo bool
	Rows    []PoolPlanRow
}

// dragAttr renders the grip's draggable attribute. The HTML draggable attribute is
// enumerated (not boolean): it must be the literal "true"/"false" - a bare
// `draggable` reads as "auto" (not draggable). Only the editable plan is draggable.
func dragAttr(v PoolPlanView) string {
	if v.EditAction != "" {
		return "true"
	}
	return "false"
}

// ppField builds an entry's form-field name: "<prefix>[<idx>][<field>]".
func ppField(prefix string, idx int, field string) string {
	return prefix + "[" + itoa(idx) + "][" + field + "]"
}

// ppOp builds the Datastar @post expression for a pool-plan edit op, posting the
// enclosing form so the server sees the full plan. The current mode + active size
// ride along so ops that aren't mode/size changes preserve them.
func ppOp(v PoolPlanView, op string, idx int, value string) string {
	if v.EditAction == "" {
		return "" // inert (static-render / read-only)
	}
	q := v.EditAction + "?s=" + itoa(v.Scope) + "&op=" + op + "&mode=" + v.Mode + "&size=" + v.ActiveSize
	if idx >= 0 {
		q += "&i=" + itoa(idx)
	}
	if value != "" {
		q += "&v=" + value
	}
	return "@post('" + q + "', {contentType:'form'})"
}

// ppOn returns the Datastar event attribute (e.g. data-on:click) for a pool-plan
// op, or no attribute at all when the editor is inert (EditAction == ""). Emitting
// an empty data-on:click="" makes Datastar throw ValueRequired, so a read-only
// render (static preview / a non-editing /pools) must omit the attribute entirely.
func ppOn(v PoolPlanView, event, op string, idx int, value string) templ.Attributes {
	expr := ppOp(v, op, idx, value)
	if expr == "" {
		return nil
	}
	return templ.Attributes{"data-on:" + event: expr}
}

// planHeading returns the head title, defaulting to "Pool plan".
func planHeading(v PoolPlanView) string {
	if v.Heading == "" {
		return "Pool plan"
	}
	return v.Heading
}

// reserveSummary builds the read-only foot line: the appliance/DHCP-server
// address + each Reserve row's label and size. "DHCP server" (not "Gateway") -
// the .1 address is the appliance itself, only a real gateway when an uplink is
// active. CSS truncates with an ellipsis (never wraps), so under space pressure
// only the leading entries show.
func reserveSummary(v PoolPlanView) string {
	out := "DHCP server " + v.Gateway
	for _, p := range v.Rows {
		if p.Reserve {
			out += " · " + p.Name + " (" + itoa(p.Count) + ")"
		}
	}
	return out
}

// clampPct bounds a percentage to [0,100] for a meter fill width (an elastic
// pool can momentarily report >100% if leases outrun the computed capacity).
func clampPct(p int) int {
	switch {
	case p < 0:
		return 0
	case p > 100:
		return 100
	default:
		return p
	}
}

// --- DHCP Pools (/pools) ---

// PoolsView is the dedicated pool-management page: the active profile's scopes,
// each rendered as a PoolPlan (full editing) with the live Utilization column.
type PoolsView struct {
	Page     PageData
	Scopes   []PoolScopeView
	Profiles []ProfileOption // for the shared Manage dropdown (switch/edit/new)
}

// PoolScopeView pairs a scope's heading with its pool plan and network services.
type PoolScopeView struct {
	Title    string // e.g. "Green-GO Intercom · 10.0.0.0/24" or "VLAN 20 · …"
	Plan     PoolPlanView
	Services ScopeServicesView
	// UplinkEnabled is this scope's per-scope "route through the WiFi uplink" toggle;
	// UplinkAvailable is the box-level master enable (when off, the toggle is inert and
	// shown disabled with a hint pointing at Settings).
	UplinkEnabled   bool
	UplinkAvailable bool
}

// ScopeServicesView is the per-scope DHCP "Network services" panel (explicit
// gateway/DNS override, lease-lifetime override, extra DHCP options). It is shared
// by the /pools editor and the setup wizard via FieldPrefix: "" yields plain field
// names (gateway/dns/lease/opt_name[]/opt_data[]) for the per-scope /pools form;
// "scopes[__ID__]" yields the wizard's cloned-template names. Both surfaces save
// through their enclosing form's single button (the /pools pool-plan "Save changes"
// or the wizard's /setup/apply) - there is no separate services Save. RegionID is set
// only on /pools (the morph target for re-rendering after that scope's save).
type ScopeServicesView struct {
	FieldPrefix    string // "" (/pools) or "scopes[__ID__]" (wizard)
	RegionID       string // morph target on /pools, e.g. "svc-0"; "" in the wizard
	Gateway        string
	DNS            string
	Lease          string // lease override as text; "" = inherit global
	DerivedGateway string // the .1 hint shown as the gateway placeholder
	GlobalLease    int    // global default, shown as the lease placeholder
	Options        []ScopeOptionRow
}

// ScopeOptionRow is one extra-DHCP-option input row (name + data).
type ScopeOptionRow struct {
	Name string
	Data string
}

// svcField builds a network-services field name honoring the FieldPrefix.
func svcField(v ScopeServicesView, name string) string {
	if v.FieldPrefix == "" {
		return name
	}
	return v.FieldPrefix + "[" + name + "]"
}

// optionRows returns the per-scope saved option rows plus ONE blank row to type into.
func optionRows(v ScopeServicesView) []ScopeOptionRow { return withBlankRow(v.Options) }

// withBlankRow appends one empty row so there is always something to type into; the
// "Add option" button (ggoAddDhcpOption) clones it for more, and empty rows are
// dropped on save. Shared by the per-scope card and the global /settings card.
func withBlankRow(rows []ScopeOptionRow) []ScopeOptionRow {
	return append(append([]ScopeOptionRow{}, rows...), ScopeOptionRow{})
}

// optField builds an extra-option input name. An empty prefix yields the plain
// repeated name (opt_name[]) for the global /settings form; a prefix yields the
// wizard's cloned-scope name (scopes[__ID__][opt_name][]).
func optField(prefix, name string) string {
	if prefix == "" {
		return name + "[]"
	}
	return prefix + "[" + name + "][]"
}

// --- Leases ---

type LeasesView struct {
	Page       PageData
	Leases     []LeaseRow // unified: active leases + client reservations (Reserved flag)
	CanReserve bool       // MariaDB host store online
	Error      string
}

// LeaseRow is one active DHCP lease as displayed.
type LeaseRow struct {
	IPAddress string
	HWAddress string
	ClientID  string
	Hostname  string
	Class     string
	ExpiresIn string
	// ExpiresAt is the absolute lease-expiry epoch (seconds): >0 a real expiry the
	// client counts down live (data-expires), 0 unknown, -1 infinite ("never").
	// Absolute so a cached/rebroadcast fragment never shows a stale countdown.
	ExpiresAt int64
	// Presence is the online/offline signal from the active ARP prober, keyed by this
	// row's IP: "online" (the device at this address answered an ARP recently), "offline"
	// (no answer), or "" (unknown - probing unavailable, so no indicator is shown).
	Presence string
	// Reserved is true when this device's MAC has a client (hardware-address) host
	// reservation - i.e. its IP is fixed, not dynamic. SubnetID is the reservation's
	// Kea subnet (needed to remove it).
	Reserved bool
	SubnetID int
	// PortPinned is true when this lease arrives on a switch port that has a flex-id
	// (Option-82) pin: the IP is fixed by the port, not the MAC. Such a device's IP is
	// governed by the port reservation (flex-id wins over hw-address in Kea's
	// host-reservation-identifiers order), so the leases page must NOT offer a MAC
	// reservation for it - that reservation would be silently shadowed. The row renders
	// like a reservation but its delete control is disabled (manage it on Port Pinning).
	PortPinned bool
	// LastSeen is the epoch (0 = never observed) the MAC was last active; LastSeenText
	// is its coarse "3d ago" rendering; Stale flags a reservation unseen for a long time.
	LastSeen     int64
	LastSeenText string
	Stale        bool
}

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
	case "", "none", "absent", "ok", "gone", "static", "link-local":
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

// --- Port pinning ---

type PinningView struct {
	Page      PageData
	Error     string
	Pinned    []PortRow // bound reservations
	Learnable []PortRow // Option-82 ports seen live but not yet pinned
}

// PortRow is one switch-port identity (pinned reservation and/or live lease). The
// Option-82 remote-id and circuit-id are kept as separate fields, each rendered two
// ways: a best-effort ASCII view (RemoteID/CircuitID) and the exact colon-hex
// (RemoteIDHex/CircuitIDHex). The /pinning ASCII/hex toggle picks which to show;
// PortIdentity is the opaque key posted in forms and used to match reservations.
type PortRow struct {
	PortIdentity string
	RemoteID     string
	RemoteIDHex  string
	CircuitID    string
	CircuitIDHex string
	IPAddress    string
	HWAddress    string
	Hostname     string
	SubnetID     int
	Label        string
	Pinned       bool
	// LastSeen is the epoch (0 = never observed) the port was last active; LastSeenText
	// is its coarse "3d ago" rendering and Stale flags a long-gone pinned port.
	LastSeen     int64
	LastSeenText string
	Stale        bool
}

// portOnline reports whether a pinned port currently has a matching live lease
// (the merge sets HWAddress to "-" for a pinned-but-offline port).
func portOnline(p PortRow) bool {
	return p.HWAddress != "" && p.HWAddress != "-"
}

// portLabel is a readable one-line identity for compact contexts (the dashboard
// pinnings card): the ASCII remote-id and circuit-id joined by " / ", falling back
// to either half, then to the opaque key when neither decoded to text.
func portLabel(p PortRow) string {
	switch {
	case p.RemoteID != "" && p.CircuitID != "":
		return p.RemoteID + " / " + p.CircuitID
	case p.RemoteID != "":
		return p.RemoteID
	case p.CircuitID != "":
		return p.CircuitID
	default:
		return p.PortIdentity
	}
}

// labelSaveOnSubmit / labelSaveOnBlur are the Datastar expressions that autosave a
// port label. Both set the CSRF token from the page <meta> at event time (the live
// SSE broadcast re-renders the rows with an empty token) before @post-ing the form.
// Submit (Enter) reads the form via el; blur reads the input's enclosing form.
func labelSaveOnSubmit() string {
	return "el.querySelector('[name=csrf_token]').value=document.querySelector('meta[name=csrf-token]').content;@post('/pinning/label',{contentType:'form'})"
}

func labelSaveOnBlur() string {
	return "el.closest('form').querySelector('[name=csrf_token]').value=document.querySelector('meta[name=csrf-token]').content;@post('/pinning/label',{contentType:'form'})"
}

// meterClass returns the meter fill variant for an occupancy percentage:
// amber ≥80%, red ≥95% (DESIGN.md §8). Used by the pool table.
func meterClass(percent int) string {
	switch {
	case percent >= 95:
		return "err"
	case percent >= 80:
		return "warn"
	default:
		return ""
	}
}

// poolsOverallPct is leased / capacity across every DHCP pool, clamped 0-100
// (elastic pools can momentarily read over capacity). Mirrors the web build's
// overallPoolUtil so the collapsed-header rollup and the tiles agree.
func poolsOverallPct(pools []PoolRow) int {
	var allocated, capacity int
	for _, p := range pools {
		allocated += p.Allocated
		capacity += p.Capacity
	}
	if capacity <= 0 {
		return 0
	}
	if pct := allocated * 100 / capacity; pct < 100 {
		return pct
	}
	return 100
}

// poolsRollupClass picks the collapsed-header pill variant from overall pool
// utilization, reusing the meter thresholds (>=95 err, >=80 warn).
func poolsRollupClass(pools []PoolRow) string {
	if len(pools) == 0 {
		return ""
	}
	switch meterClass(poolsOverallPct(pools)) {
	case "err":
		return "is-err"
	case "warn":
		return "is-warn"
	default:
		return "is-ok"
	}
}

// poolsRollupText summarizes overall utilization for the collapsed pools header.
func poolsRollupText(pools []PoolRow) string {
	if len(pools) == 0 {
		return "No pools"
	}
	return itoa(poolsOverallPct(pools)) + "% used"
}

// poolsRollupDetail is the hover tooltip on the collapsed pools pill: pool count,
// total addresses in use, and the busiest pool - so the operator gets the detail
// without expanding the card.
func poolsRollupDetail(pools []PoolRow) string {
	if len(pools) == 0 {
		return "No DHCP pools allocated yet."
	}
	var used, capacity int
	busiest := pools[0]
	for _, p := range pools {
		used += p.Allocated
		capacity += p.Capacity
		if p.Percent > busiest.Percent {
			busiest = p
		}
	}
	return itoa(len(pools)) + " " + pluralize(len(pools), "pool", "pools") + " · " +
		itoa(used) + "/" + itoa(capacity) + " addresses in use · busiest " +
		busiest.Label + " " + itoa(busiest.Percent) + "%"
}

// --- Network Health (passive monitoring card) ---

// NetHealthView is the dashboard's Network Health card model: one block per
// monitored interface, each with the per-detector signal rows. The backend emits
// structured signals (severity/kind/subject/text) - this view maps them to
// presentation; it bakes in no HTML of its own.
type NetHealthView struct {
	Interfaces []NetHealthIface
	// Firmware holds one row per Green-GO model family running mixed firmware (from
	// the active 6464 scan). Empty when the fleet is uniform or no scan is running.
	Firmware []FirmwareModelRow
}

// FirmwareModelRow is one model family's firmware mismatch: a one-line summary for
// the card and the per-device breakdown for the info-tip tooltip (capped, with More
// counting any devices beyond the cap).
type FirmwareModelRow struct {
	Summary string
	Devices []FirmwareDeviceRow
	More    int
}

// FirmwareDeviceRow is one device in a firmware-mismatch tooltip.
type FirmwareDeviceRow struct {
	Name    string
	IP      string
	Version string
}

// NetHealthIface is one monitored interface's health: its detector rows plus the
// honest governor/availability state (so the card can say "multicast inspection
// paused - high load" or "monitoring unavailable").
type NetHealthIface struct {
	Iface     string
	ScopeName string // friendly scope name for the card title ("" -> show Iface alone)
	Available bool
	Note      string // honest state when not fully available / shedding
	Level     string // governor level ("full", "no-promiscuous", "counters-only", "paused")
	Degraded  bool   // governor is shedding (Level != full) or unavailable
	LinkMode  string // "flat"/"trunk"/"" - shown in the rollup header
	OKCount   int    // rollup of Rows by severity
	WarnCount int
	ErrCount  int
	Rows      []NetHealthRow
}

// NetHealthRow is one detector's signal. Severity is "ok"|"info"|"warn"|"error";
// Detail is an optional secondary line (subject/MAC/port) the card shows muted.
type NetHealthRow struct {
	Kind     string
	Severity string
	Title    string
	Detail   string
	// DetailRows, when set, renders the tooltip as one line per entry (e.g. a device
	// roster: "BPX 10.0.0.24 (00:1f:80:…)" per row) instead of one wrapping blob.
	DetailRows []string
}

// LLDPChip is the config-card "you are here" chip derived from the LLDP neighbor.
type LLDPChip struct {
	Present    bool
	Switch     string
	Port       string
	NativeVLAN string
}

// AlertRow is a backend-health signal (Kea down, MariaDB down, Wi-Fi uplink down)
// rendered in the always-on #backend-alert strip above the page h1: Severity
// ("err"/"warn") picks the .alert variant (alertClass) and Title+Detail are the
// strip's lines. (Netmon signals go to the header pill instead - see StatusPillView.)
type AlertRow struct {
	Severity string
	Title    string
	Detail   string
}

// alertClass maps an AlertRow severity ("err"/"warn") to its .alert variant class.
func alertClass(sev string) string {
	if sev == "err" {
		return "alert-err"
	}
	return "alert-warn"
}

// PTPRow is one PTP-domain clock signal for the PTP panel.
type PTPRow struct {
	Severity   string
	Domain     string // "domain N"
	Text       string
	ClockClass int // grandmaster's advertised clockClass (-1 if unknown/absent)
}

// PTPQuality maps a PTP grandmaster clockClass (IEEE 1588-2008 Table 5) to an
// operator-facing lock state and a status-dot severity. clockClass is the GM's
// advertised sync quality: 6 = locked to a primary reference (GPS/atomic), 7 =
// holdover (reference lost, still within spec), the degraded buckets are out of
// spec, and 248 is a free-running default master - normal in a self-contained
// Green-GO network, so it is neutral rather than alarming. The useful signal is a
// *change* (e.g. 6 -> 7 -> 248 = a GM that lost its GPS lock).
func PTPQuality(clockClass int) (label, dot string) {
	switch clockClass {
	case 6:
		return "GPS", "ok" // locked to a primary reference (commonly GPS)
	case 13:
		return "Locked", "ok" // locked to an arbitrary (ARB) timescale
	case 7, 14:
		return "Holdover", "warn"
	case 52, 58, 187, 193:
		return "Degraded", "warn"
	case 248:
		return "Local", "" // free-running default master - normal/neutral in a closed net
	case 255:
		return "Slave", "warn" // a slave-only clock acting as GM is odd
	default:
		if clockClass < 0 {
			return "Present", "ok" // a GM is present but did not advertise a class we read
		}
		return "Class " + itoa(clockClass), ""
	}
}

// presenceDot maps a lease's passive online/offline signal to a status-dot variant:
// online is a green ok dot, offline a neutral (muted) dot - meaning is reinforced by
// the cell's title tooltip, never color alone.
func presenceDot(presence string) string {
	if presence == "online" {
		return "ok"
	}
	return "" // offline → neutral/muted dot
}

// presenceTitle is the hover/aria text for the lease availability dot - "online"/
// "offline" alone is terse, so spell out what the passive monitor means by it.
func presenceTitle(presence string) string {
	switch presence {
	case "online":
		return "Online - answered a recent ARP probe"
	case "offline":
		return "Offline - no reply to the ARP probe"
	default:
		return ""
	}
}

// netHealthDot maps a detector severity to the status-dot variant (ok/warn/err;
// info is a neutral muted dot - informational signals must not read as alarms).
// netRowShowTip reports whether a detector row gets an info bubble: only when it
// carries machine detail distinct from the row text. Echoing the title (the old
// long-title fallback) just repeated the whole row in the tooltip, which operators
// read as noise - the detail must ADD something (a MAC, a port, the full census).
func netRowShowTip(r NetHealthRow) bool {
	return len(r.DetailRows) > 0 || (r.Detail != "" && r.Detail != r.Title)
}

// netRowTip is the bubble's text: the machine detail (only shown when distinct from
// the title, per netRowShowTip).
func netRowTip(r NetHealthRow) string {
	return r.Detail
}

func netHealthDot(severity string) string {
	switch severity {
	case "ok":
		return "ok"
	case "warn":
		return "warn"
	case "error":
		return "err"
	default: // info / unknown → neutral
		return ""
	}
}

// netRollupClass picks the per-interface rollup pill variant from the worst
// detector severity (only called when the interface is available): any error →
// err, any warning → warn, otherwise ok.
func netRollupClass(ifc NetHealthIface) string {
	switch {
	case ifc.ErrCount > 0:
		return "is-err"
	case ifc.WarnCount > 0:
		return "is-warn"
	default:
		return "is-ok"
	}
}

// netRollupDot maps an interface's worst severity to the header status-dot variant
// (err/warn/ok); an unavailable interface is neutral (no color) rather than a
// misleading green.
func netRollupDot(ifc NetHealthIface) string {
	switch {
	case !ifc.Available:
		return ""
	case ifc.ErrCount > 0:
		return "err"
	case ifc.WarnCount > 0:
		return "warn"
	default:
		return "ok"
	}
}

// netSubcardClass gives the interface sub-card its severity accent (a colored left
// border via sev-warn/sev-err); ok and unavailable carry no accent.
func netSubcardClass(ifc NetHealthIface) string {
	if !ifc.Available {
		return ""
	}
	switch {
	case ifc.ErrCount > 0:
		return "sev-err"
	case ifc.WarnCount > 0:
		return "sev-warn"
	default:
		return ""
	}
}

// netRollupText summarizes an interface's detector counts for the rollup pill:
// the worst nonzero count leads (those counts are meaningful problem totals),
// falling back to "Healthy" when every detector is OK, then "monitoring" when
// nothing has been observed yet. The all-OK count itself ("6 ok") was dropped -
// it counted passive detectors, not anything an operator can act on, and read as
// a mystery number next to the per-detector dots already listed below.
func netRollupText(ifc NetHealthIface) string {
	switch {
	case ifc.ErrCount > 0:
		return itoa(ifc.ErrCount) + " " + pluralize(ifc.ErrCount, "alert", "alerts")
	case ifc.WarnCount > 0:
		return itoa(ifc.WarnCount) + " " + pluralize(ifc.WarnCount, "warning", "warnings")
	case ifc.OKCount > 0:
		return "Healthy"
	default:
		return "monitoring"
	}
}

// netOverall sums detector counts across every interface plus how many are
// available, feeding the collapsed network-health header's combined rollup.
func netOverall(v NetHealthView) (ok, warn, err, avail int) {
	for _, ifc := range v.Interfaces {
		if ifc.Available {
			avail++
		}
		ok += ifc.OKCount
		warn += ifc.WarnCount
		err += ifc.ErrCount
	}
	// A firmware mismatch is cross-cutting (not tied to one interface); count each
	// mismatched model family as a warning so the collapsed card reflects it.
	warn += len(v.Firmware)
	return
}

// netOverallClass picks the combined rollup pill variant from the worst severity
// seen on any interface; with nothing monitored yet it stays neutral (no tint).
func netOverallClass(v NetHealthView) string {
	ok, warn, err, avail := netOverall(v)
	switch {
	case err > 0:
		return "is-err"
	case warn > 0:
		return "is-warn"
	case avail == 0:
		return ""
	case ok > 0:
		return "is-ok"
	default:
		return ""
	}
}

// netOverallText summarizes combined health for the collapsed header: the worst
// nonzero count leads, then "All clear" once interfaces report, then the idle
// placeholder before any monitoring has happened.
func netOverallText(v NetHealthView) string {
	ok, warn, err, avail := netOverall(v)
	switch {
	case err > 0:
		return itoa(err) + " " + pluralize(err, "alert", "alerts")
	case warn > 0:
		return itoa(warn) + " " + pluralize(warn, "warning", "warnings")
	case avail == 0:
		return "Monitoring idle"
	case ok > 0:
		return "All clear"
	default:
		return "Monitoring"
	}
}

// netHealthRollupDetail is the hover tooltip on the collapsed network-health pill:
// the active warnings/alerts across every interface (capped so the tooltip stays
// readable), or a reassuring "no issues" line - context without expanding the card.
func netHealthRollupDetail(v NetHealthView) string {
	_, _, _, avail := netOverall(v)
	if avail == 0 {
		return "Passive monitoring starts once a profile is active."
	}
	var issues []string
	for _, fw := range v.Firmware {
		issues = append(issues, "firmware: "+fw.Summary)
	}
	for _, ifc := range v.Interfaces {
		for _, r := range ifc.Rows {
			if r.Severity == "warn" || r.Severity == "error" {
				issues = append(issues, ifc.Iface+": "+r.Title)
			}
		}
	}
	if len(issues) == 0 {
		return itoa(avail) + " " + pluralize(avail, "interface", "interfaces") + " monitored · no issues detected"
	}
	if len(issues) > 4 {
		more := len(issues) - 4
		return strings.Join(issues[:4], " · ") + " · +" + itoa(more) + " more"
	}
	return strings.Join(issues, " · ")
}

// pinningsRollupDetail is the hover tooltip on the collapsed port-pinnings pill:
// the first few pinned ports and their fixed IPs, so the operator sees what is
// pinned without expanding the card.
func pinningsRollupDetail(rows []PortRow) string {
	if len(rows) == 0 {
		return "No switch ports pinned. Pin a port to give its device a fixed IP."
	}
	var parts []string
	for i, p := range rows {
		if i >= 3 {
			break
		}
		parts = append(parts, portLabel(p)+" → "+p.IPAddress)
	}
	out := strings.Join(parts, " · ")
	if len(rows) > 3 {
		out += " · +" + itoa(len(rows)-3) + " more"
	}
	return out
}

// lldpChipText assembles the LLDP "you are here" chip label from the neighbor's
// switch, port, and (when advertised) native VLAN, joining only the parts that
// are present so a missing port/VLAN leaves no dangling separator.
func lldpChipText(c LLDPChip) string {
	head := c.Switch
	if c.Port != "" {
		head += " (" + c.Port + ")"
	}
	parts := []string{head}
	if c.NativeVLAN != "" {
		parts = append(parts, "VLAN "+c.NativeVLAN)
	}
	return strings.Join(parts, " · ")
}

// netHealthIcon maps a detector kind to its card glyph (all Lucide names that
// exist under views/icons/).
func netHealthIcon(kind string) string {
	switch kind {
	case "igmp":
		return "network"
	case "lldp":
		return "ethernet-port"
	case "rogue_dhcp":
		return "shield"
	case "duplicate_ip":
		return "copy" // two devices claiming one address - duplication, not a generic alert
	case "ptp":
		return "clock"
	case "storm":
		return "activity"
	case "idle":
		return "cable" // link carrying no traffic
	case "sacn":
		return "cpu"
	case "vlan":
		return "layers"
	case "static_in_pool":
		return "pin" // a fixed/static address sitting inside a dynamic pool
	case "greengo":
		return "headset" // Green-GO intercom device census
	case "greengo_config":
		return "sliders-horizontal" // the active Green-GO intercom configuration
	default:
		return "circle"
	}
}
