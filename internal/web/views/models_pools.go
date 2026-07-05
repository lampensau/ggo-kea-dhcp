package views

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
	RegionID       string // panel id, unique per scope: "svc-0" (/pools morph target) or "svc-__ID__" (wizard)
	Gateway        string
	DNS            string
	LocalDNS       bool   // hand this appliance out as the scope's DNS server
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

// svcID builds a DOM id for a services control so each visible label can associate
// with its input via for/id (a11y). RegionID is unique per panel ("svc-N" on /pools,
// "svc-__ID__" in the wizard, made unique when the template is cloned per scope).
func svcID(v ScopeServicesView, name string) string {
	return v.RegionID + "-" + name
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
