package views

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
	// RawHostname is the pre-funnel name captured before the sanitize+dedupe pass
	// rewrote Hostname; the pin dialog prefills from it so an ephemeral "-0001"
	// display tag is never stored permanently.
	RawHostname string
	SubnetID    int
	Label       string
	Pinned      bool
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
