package views

import (
	"github.com/a-h/templ"
)

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
// auditDot maps an audit Result to the activity-feed dot class. Result strings
// have drifted into synonyms over time (SUCCESS/OK, ERROR/FAILED/FAILURE), so we
// normalize by category here rather than at every call site: any failure token is
// red, any success token is green, WARNING is amber, and informational rows
// (INFO, or anything unrecognized) stay neutral.
func auditDot(result string) string {
	switch result {
	case "ERROR", "FAILED", "FAILURE":
		return "err"
	case "WARNING":
		return "warn"
	case "OK", "SUCCESS":
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
