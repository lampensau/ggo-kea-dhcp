package web

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// seedActiveProfile inserts an active profile with one greengo scope (no explicit
// pool plan) and returns its scope row id.
func seedActiveProfile(t *testing.T, s *Server) int {
	t.Helper()
	res, err := s.sqlite.Exec("INSERT INTO profiles (name, active) VALUES ('Test', 1)")
	if err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	pid, _ := res.LastInsertId()
	sr, err := s.sqlite.Exec(
		`INSERT INTO scopes (profile_id, iface_mode, vlan_id, cidr, preset, pool_spec, uplink_json)
		 VALUES (?, 'physical', 0, '10.0.0.0/24', 'greengo', '{}', '{}')`, pid)
	if err != nil {
		t.Fatalf("insert scope: %v", err)
	}
	sid, _ := sr.LastInsertId()
	return int(sid)
}

// poolFormValues serializes a plan into the editor's scopes[s][pool][i][...] form
// fields, mirroring what the rendered PoolPlan posts back.
func poolFormValues(plan PoolPlan, prefix string) url.Values {
	v := url.Values{}
	for i, e := range plan {
		base := prefix + "[" + strconv.Itoa(i) + "]"
		v.Set(base+"[kind]", e.Kind)
		v.Set(base+"[class]", e.Class)
		v.Set(base+"[name]", e.Name)
		v.Set(base+"[sizing]", e.Sizing)
		v.Set(base+"[icon]", e.Icon)
		v.Set(base+"[count]", strconv.Itoa(e.Count))
		v.Set(base+"[weight]", strconv.Itoa(e.Weight))
		v.Set(base+"[range]", e.Range)
	}
	return v
}

// TestHandlePoolsPlanOp_AddPool exercises the /pools op endpoint: it posts the
// seeded plan, applies add-pool, and expects the morphed region to carry the new
// pool wired for editing.
func TestHandlePoolsPlanOp_AddPool(t *testing.T) {
	s, _ := newTestServer(t)
	seedActiveProfile(t, s)

	// Forecast counts so the seed has several Fixed device pools (with ranges) plus
	// the elastic BPX + catch-all - enough to exercise the reflow after an add.
	seeded := seedPlan(ScopeConfig{Preset: "greengo", CIDR: "10.0.0.0/24", Counts: DeviceCounts{
		MCX: 10, MCD: 4, Interface: 4, WPX: 8, WAA: 14, Others: 18,
	}})
	form := poolFormValues(seeded, "scopes[0][pool]")
	req := httptest.NewRequest("POST", "/pools/edit?s=0&op=add-pool&mode=simple", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handlePoolsPlanOp(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `id="poolplan-0"`) {
		t.Errorf("response missing morph region id; got:\n%s", body[:min(len(body), 400)])
	}
	if !strings.Contains(body, "New pool") {
		t.Errorf("add-pool op did not introduce a new pool row")
	}
	// The morphed region must stay wired for editing (and never emit an empty handler).
	if !strings.Contains(body, "@post(") {
		t.Errorf("morphed region is not wired for editing")
	}
	if strings.Contains(body, `data-on:click=""`) {
		t.Errorf("morphed region emitted an empty data-on:click")
	}
	// Simple-mode reflow guard: the seeded greengo pools are count 0 → they floor to
	// the min pool size and must KEEP ranges after the add (the range-disappear bug
	// was these vanishing because the computed range round-tripped as a stale pin).
	if n := strings.Count(body, " - 10.0.0."); n < 6 {
		t.Errorf("expected the existing pools to keep ranges after add-pool, found %d ranges", n)
	}
}

// TestHandlePoolsPlanSave_Persists exercises the save endpoint: it posts an edited
// plan and asserts the scope's pool_plan column is written and round-trips.
func TestHandlePoolsPlanSave_Persists(t *testing.T) {
	s, _ := newTestServer(t)
	sid := seedActiveProfile(t, s)

	plan := PoolPlan{
		{Kind: PoolKindReserve, Name: "Static reserve", Count: 18},
		{Kind: PoolKindFixed, Class: "GGO-WP-X", Name: "Wall panels", Sizing: "auto", Count: 6, Icon: "wpx"},
		{Kind: PoolKindElastic, Class: "GGO-BPX", Name: "Beltpacks", Weight: 1, Icon: "bpx"},
		{Kind: PoolKindFixed, Class: "GGO-OTHERS", Name: "Green-GO (other)", Sizing: "auto", Count: 0, Icon: "circle-help"},
		{Kind: PoolKindElastic, Class: "OTHERS", Name: "Any unmatched device", Weight: 1, Icon: "cpu"},
	}
	form := poolFormValues(plan, "scopes[0][pool]")
	req := httptest.NewRequest("POST", "/pools/save?s=0&mode=simple", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handlePoolsPlanSave(w, req)

	var stored string
	if err := s.sqlite.QueryRow("SELECT pool_plan FROM scopes WHERE id = ?", sid).Scan(&stored); err != nil {
		t.Fatalf("read pool_plan: %v", err)
	}
	if stored == "" {
		t.Fatal("pool_plan was not persisted")
	}
	var got PoolPlan
	if err := json.Unmarshal([]byte(stored), &got); err != nil {
		t.Fatalf("stored pool_plan is not valid JSON: %v", err)
	}
	if len(got) != 5 || got[1].Class != "GGO-WP-X" || got[1].Count != 6 || got[2].Kind != PoolKindElastic {
		t.Errorf("persisted plan mismatch: %+v", got)
	}
	if !strings.Contains(w.Body.String(), "saved") {
		t.Errorf("save did not emit a success toast")
	}
}
