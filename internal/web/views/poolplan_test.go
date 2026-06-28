package views

import (
	"strings"
	"testing"
)

// samplePoolPlanView is a representative plan with one fixed, one elastic, and
// one reserve row - enough to exercise every control in the editor.
func samplePoolPlanView() PoolPlanView {
	return PoolPlanView{
		RegionID: "poolplan-0",
		Subnet:   "10.0.0.0/24",
		Gateway:  "10.0.0.1",
		Mode:     "advanced", // so reserve rows + Auto-Fill render too
		FreeIPs:  100,
		Rows: []PoolPlanRow{
			{Name: "Static reserve", Reserve: true, Count: 18},
			{Name: "Beltpacks", Key: "GGO-BPX", Elastic: true, Weight: 1, Range: "10.0.0.20 - 10.0.0.254", Size: 235},
			{Name: "Wall panels", Key: "GGO-WP-X", Icon: "wpx", Count: 6, Size: 12, Range: "10.0.0.20 - 10.0.0.31", Prefix: "10.0.0.", StartPlaceholder: "20", EndPlaceholder: "31"},
		},
	}
}

// TestPoolPlanInertEmitsNoEmptyHandler guards the live Datastar bug: a read-only
// render (EditAction == "", e.g. the non-editing /pools view or static preview)
// must NOT emit an empty data-on:click="" - Datastar throws ValueRequired on it.
func TestPoolPlanInertEmitsNoEmptyHandler(t *testing.T) {
	v := samplePoolPlanView()
	v.EditAction = "" // inert
	v.SizePresets = true
	html := render(t, PoolPlan(v))

	for _, bad := range []string{`data-on:click=""`, `data-on:change=""`} {
		if strings.Contains(html, bad) {
			t.Errorf("inert render emitted %s (Datastar ValueRequired)", bad)
		}
	}
	// An inert render carries no @post handlers at all.
	if strings.Contains(html, "@post(") {
		t.Errorf("inert render should not wire any @post handler")
	}
}

// TestPoolPlanSimpleModeKeepsReserveFields guards the Simple-mode op bug: a Reserve
// row is hidden from the Simple table, but its hidden plan fields MUST still post or
// the server reconstructs a truncated plan and every op no-ops. The static reserve
// is index 0, so its fields must appear even though its visible row does not.
func TestPoolPlanSimpleModeKeepsReserveFields(t *testing.T) {
	v := samplePoolPlanView()
	v.Mode = "simple"
	v.EditAction = "/pools/edit"
	v.FieldPrefix = "scopes[0][pool]"
	html := render(t, PoolPlan(v))

	// index 0 is the static reserve; its kind field must be present in Simple mode.
	if !strings.Contains(html, `name="scopes[0][pool][0][kind]"`) {
		t.Errorf("Simple-mode render dropped the hidden reserve row fields (ops would no-op)")
	}
	// ...but the reserve's visible editable name input must NOT show in Simple.
	if strings.Contains(html, `class="form-control form-control-sm pp-name-input" value="Static reserve"`) {
		t.Errorf("Simple-mode render should hide the reserve row's visible cells")
	}
}

// TestPoolPlanPostsOnlyExplicitRangePin guards the range-disappear bug: the
// computed DISPLAY range must never be posted back as the entry's range, or it
// round-trips as a spurious pin that stops LayoutPools from reflowing on add/
// remove/reorder. Auto pools (empty RangePin) post an empty range field.
func TestPoolPlanPostsOnlyExplicitRangePin(t *testing.T) {
	// The computed display range must NEVER be posted as a value (it would read back
	// as a pin and stop reflow). In both modes an auto pool (empty RangePin) posts
	// an empty range; in Advanced the computed range is only a placeholder hint.

	// Simple mode: the range is a hidden field with the (empty) pin.
	simple := samplePoolPlanView() // Wall panels (idx 2): computed Range, empty RangePin
	simple.Mode = "simple"
	simple.EditAction = "/pools/edit"
	simple.FieldPrefix = "scopes[0][pool]"
	html := render(t, PoolPlan(simple))
	if strings.Contains(html, `value="10.0.0.20 - 10.0.0.31"`) {
		t.Errorf("simple: computed range leaked into a posted value (spurious pin)")
	}
	if !strings.Contains(html, `name="scopes[0][pool][2][range]" value=""`) {
		t.Errorf("simple: auto pool should post an empty range field")
	}

	// Advanced mode: the range is split into editable start/end host inputs.
	// Values are empty (the auto pool has no RangePin). Placeholders are the computed host parts.
	adv := simple
	adv.Mode = "advanced"
	html = render(t, PoolPlan(adv))
	if strings.Contains(html, `value="20"`) || strings.Contains(html, `value="31"`) {
		t.Errorf("advanced: computed range leaked into input values (spurious pin)")
	}
	if !strings.Contains(html, `placeholder="20"`) || !strings.Contains(html, `placeholder="31"`) {
		t.Errorf("advanced: computed range host parts should show as input placeholder hints")
	}
	if !strings.Contains(html, `scopes[0][pool][2][range_start]`) || !strings.Contains(html, `scopes[0][pool][2][range_end]`) {
		t.Errorf("advanced: input field names should be range_start and range_end")
	}
}

// TestPoolPlanFixedShowsIPCount verifies a Fixed pool surfaces its reserved IP
// count after the range (Simple-mode headroom makes the IPs differ from the device
// count, so the count is shown like the elastic pool's "N IPs").
func TestPoolPlanFixedShowsIPCount(t *testing.T) {
	v := samplePoolPlanView() // Wall panels (fixed) Size 12
	v.Mode = "simple"
	html := render(t, PoolPlan(v))
	if !strings.Contains(html, "12 IPs") {
		t.Errorf("fixed pool did not show its reserved IP count")
	}
}

// TestPoolPlanLockedRowHasNoRemove verifies the "Any unmatched device" catch-all
// (Locked) renders without a remove button, while normal pools keep theirs.
func TestPoolPlanLockedRowHasNoRemove(t *testing.T) {
	v := PoolPlanView{
		Mode: "advanced", EditAction: "/pools/edit", FieldPrefix: "scopes[0][pool]",
		Rows: []PoolPlanRow{
			{Name: "Wall panels", Key: "GGO-WP-X", Count: 6, Size: 12},
			{Name: "Any unmatched device", Elastic: true, Weight: 1, Locked: true, Size: 60},
		},
	}
	html := render(t, PoolPlan(v))
	// Exactly one remove button (the non-locked pool); the locked catch-all has none.
	if n := strings.Count(html, `class="pp-remove"`); n != 1 {
		t.Errorf("expected exactly 1 remove button (locked row has none), got %d", n)
	}
}

// TestPoolPlanEditableWiresHandlers verifies the editing render does emit the
// op handlers (the inert guard above must not over-suppress).
func TestPoolPlanEditableWiresHandlers(t *testing.T) {
	v := samplePoolPlanView()
	v.EditAction = "/setup/pools/edit"
	v.FieldPrefix = "scopes[0][pool]"
	v.SizePresets = true
	html := render(t, PoolPlan(v))

	// templ HTML-escapes the attribute value ('→&#39;, &→&amp;); the browser reads
	// the de-escaped DOM value, so assert on the escaped on-disk form.
	if !strings.Contains(html, `data-on:click="@post(&#39;/setup/pools/edit`) {
		t.Errorf("editable render missing wired click handler")
	}
	// No empty handler should slip through even when editable.
	if strings.Contains(html, `data-on:click=""`) {
		t.Errorf("editable render emitted an empty data-on:click")
	}
}

// TestPoolPlanRecomputeTrigger verifies the hidden recompute trigger button's presence.
func TestPoolPlanRecomputeTrigger(t *testing.T) {
	// 1. When editable: the trigger should exist and wire @post(..., op=recompute)
	v := samplePoolPlanView()
	v.EditAction = "/setup/pools/edit"
	html := render(t, PoolPlan(v))
	if !strings.Contains(html, `class="pp-recompute-trigger"`) {
		t.Errorf("editable render missing pp-recompute-trigger button")
	}
	if !strings.Contains(html, `op=recompute`) {
		t.Errorf("recompute trigger button should target op=recompute")
	}

	// 2. When inert: the trigger should have no data-on:click
	v.EditAction = ""
	htmlInert := render(t, PoolPlan(v))
	if strings.Contains(htmlInert, `op=recompute`) {
		t.Errorf("inert render should not wire op=recompute on trigger button")
	}
}
