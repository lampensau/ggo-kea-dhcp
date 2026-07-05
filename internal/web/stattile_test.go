package web

import (
	"reflect"
	"testing"

	"ggo-kea-dhcp/internal/web/views"
)

func TestSharedMSScaleIgnoresNegatives(t *testing.T) {
	sc := sharedMSScale([]int{-1, -1, 12, 30}, []int{5, 8})
	if !sc.ok || sc.lo != 5 || sc.hi != 30 {
		t.Fatalf("sharedMSScale = %+v, want ok lo=5 hi=30 (negatives ignored)", sc)
	}
	// One-sided: an all-sentinel uplink degenerates to the RTT series' own range.
	sc = sharedMSScale([]int{-1, -1, -1}, []int{6, 9, 7})
	if !sc.ok || sc.lo != 6 || sc.hi != 9 {
		t.Fatalf("sharedMSScale one-sided = %+v, want ok lo=6 hi=9", sc)
	}
}

func TestSharedMSScaleDegenerate(t *testing.T) {
	// All-negative/empty input: no scale, and the render helpers fall back to the
	// per-series normalization (byte-identical to the unscaled functions).
	for _, sc := range []msScale{
		sharedMSScale([]int{-1, -1}, nil),
		sharedMSScale(),
	} {
		if sc.ok {
			t.Fatalf("degenerate sharedMSScale = %+v, want ok=false", sc)
		}
		series := []int{-1, -1, 4}
		if got, want := sc.points(series), views.SparklinePoints(series); got != want {
			t.Errorf("fallback points = %q, want unscaled %q", got, want)
		}
		if got, want := views.AreaFromPoints(sc.points(series)), views.SparklineArea(series); got != want {
			t.Errorf("fallback area = %q, want unscaled %q", got, want)
		}
	}
}

// TestBuildStatTilesSharedMSScale proves the two millisecond tiles render on one
// scale: the series with the smaller spread no longer fills the full box height.
func TestBuildStatTilesSharedMSScale(t *testing.T) {
	snap := metricsSnapshot{
		KeaRTT: []int{6, 9, 7, 8, 6, 7, 7, 8},
		Uplink: []int{22, 31, 26, 24, 29, 27, 28, 26},
	}
	tiles := buildStatTiles(0, nil, snap, nil)
	var rtt, uplink views.StatTileView
	for _, tl := range tiles {
		switch tl.Label {
		case "Lease processing":
			rtt = tl
		case "Uplink":
			uplink = tl
		}
	}
	sc := sharedMSScale(snap.Uplink, snap.KeaRTT)
	if sc.lo != 6 || sc.hi != 31 {
		t.Fatalf("shared scale = %+v, want lo=6 hi=31", sc)
	}
	if want := views.SparklinePointsScaled(snap.KeaRTT, 6, 31); rtt.Points != want {
		t.Errorf("RTT tile points = %q, want shared-scale %q", rtt.Points, want)
	}
	if want := views.SparklinePointsScaled(snap.Uplink, 6, 31); uplink.Points != want {
		t.Errorf("Uplink tile points = %q, want shared-scale %q", uplink.Points, want)
	}
	if rtt.Points == views.SparklinePoints(snap.KeaRTT) {
		t.Error("RTT tile still renders on its own scale - shared scale not applied")
	}
}

// TestBuildStatTilesOfflineUplinkFallsBack covers the sentinel-only uplink: the
// tile shows Offline with no sparkline, and the RTT tile degenerates to its own
// range (harmless: the shared max IS the RTT max then).
func TestBuildStatTilesOfflineUplinkFallsBack(t *testing.T) {
	snap := metricsSnapshot{
		KeaRTT: []int{6, 9, 7},
		Uplink: []int{-1, -1, -1},
	}
	tiles := buildStatTiles(0, nil, snap, nil)
	for _, tl := range tiles {
		switch tl.Label {
		case "Uplink":
			if tl.Value != "Offline" || tl.Points != "" {
				t.Errorf("offline uplink tile = value %q points %q, want Offline with no sparkline", tl.Value, tl.Points)
			}
		case "Lease processing":
			if want := views.SparklinePoints(snap.KeaRTT); tl.Points != want {
				t.Errorf("RTT points with offline uplink = %q, want own-range %q", tl.Points, want)
			}
		}
	}
}

// TestBuildStatTilesOfflineUplinkDoesNotSquashRTT covers the mixed case: uplink
// just went offline (last sample the -1 sentinel) but still carries large earlier
// latencies, while Kea RTT is live. The uplink sparkline is hidden, so its history
// must not feed the shared scale - the visible RTT line has to render on its own
// range, not squashed against a 30 ms uplink ceiling it can no longer be seen next to.
func TestBuildStatTilesOfflineUplinkDoesNotSquashRTT(t *testing.T) {
	snap := metricsSnapshot{
		KeaRTT: []int{6, 9, 7, 8},
		Uplink: []int{22, 31, 26, -1}, // last sample offline -> sparkline hidden
	}
	tiles := buildStatTiles(0, nil, snap, nil)
	var rtt, uplink views.StatTileView
	for _, tl := range tiles {
		switch tl.Label {
		case "Lease processing":
			rtt = tl
		case "Uplink":
			uplink = tl
		}
	}
	if uplink.Value != "Offline" || uplink.Points != "" {
		t.Errorf("offline uplink tile = value %q points %q, want Offline with no sparkline", uplink.Value, uplink.Points)
	}
	// RTT must scale to its own [6,9] range, i.e. byte-identical to the unscaled
	// render - not to the [6,31] range the offline uplink history would impose.
	if want := views.SparklinePoints(snap.KeaRTT); rtt.Points != want {
		t.Errorf("RTT points with offline uplink = %q, want own-range %q", rtt.Points, want)
	}
	if squashed := views.SparklinePointsScaled(snap.KeaRTT, 6, 31); rtt.Points == squashed {
		t.Error("RTT tile squashed by hidden offline-uplink history - shared scale still includes it")
	}
}

// TestBuildStatTilesDeterministic guards the SSE hash contract: identical inputs
// must render identical tiles, byte for byte.
func TestBuildStatTilesDeterministic(t *testing.T) {
	snap := metricsSnapshot{
		LeaseCount: []int{30, 31, 33},
		PoolPct:    []int{40, 46, 52},
		KeaRTT:     []int{6, 9, 7, 8},
		Uplink:     []int{-1, 22, 31, 26},
	}
	a := buildStatTiles(33, nil, snap, nil)
	b := buildStatTiles(33, nil, snap, nil)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("buildStatTiles is not deterministic:\n%v\n%v", a, b)
	}
}
