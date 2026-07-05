package views

import "testing"

func TestSparklinePoints(t *testing.T) {
	cases := []struct {
		name   string
		series []int
		want   string
	}{
		{"empty", nil, ""},
		{"single sample is a centered flat line", []int{7}, "0,16 100,16"},
		{"flat series is a centered line", []int{5, 5, 5}, "0,16 50,16 100,16"},
		// rising: oldest at bottom (h-pad=30), newest at top (pad=2)
		{"rising two points", []int{0, 10}, "0,30 100,2"},
		{"three points span the width", []int{0, 5, 10}, "0,30 50,16 100,2"},
		// negatives still normalize into the box (uplink -1 sentinels etc.)
		{"negatives normalize", []int{-2, 0}, "0,30 100,2"},
	}
	for _, c := range cases {
		if got := SparklinePoints(c.series); got != c.want {
			t.Errorf("%s: SparklinePoints(%v) = %q, want %q", c.name, c.series, got, c.want)
		}
	}
}

func TestSparklineArea(t *testing.T) {
	if got := SparklineArea(nil); got != "" {
		t.Fatalf("empty area = %q, want \"\"", got)
	}
	// the line points, then the two baseline corners (viewBox 100x32) that the
	// <polygon> auto-closes back to the first point.
	if got := SparklineArea([]int{0, 10}); got != "0,30 100,2 100,32 0,32" {
		t.Fatalf("area = %q, want closed polygon", got)
	}
}

// TestSparklineUnscaledByteIdentity pins the unscaled functions to output strings
// captured BEFORE they were refactored to delegate to the scaled variants. The
// live SSE hub hashes rendered fragments, so the refactor must not move a single
// byte for existing callers.
func TestSparklineUnscaledByteIdentity(t *testing.T) {
	golden := []struct {
		series []int
		points string
		area   string
	}{
		{[]int{6, 9, 7, 8, 6, 7, 7, 8},
			"0,30 14,2 28,21 42,12 57,30 71,21 85,21 100,12",
			"0,30 14,2 28,21 42,12 57,30 71,21 85,21 100,12 100,32 0,32"},
		{[]int{22, 31, 26, 24, 29, 27, 28, 26},
			"0,30 14,2 28,18 42,24 57,9 71,15 85,12 100,18",
			"0,30 14,2 28,18 42,24 57,9 71,15 85,12 100,18 100,32 0,32"},
		{[]int{0, 250, 3},
			"0,30 50,2 100,30",
			"0,30 50,2 100,30 100,32 0,32"},
		{[]int{-1, -1, 12, 15, -1, 9},
			"0,30 20,30 40,8 60,2 80,30 100,13",
			"0,30 20,30 40,8 60,2 80,30 100,13 100,32 0,32"},
		{[]int{100},
			"0,16 100,16",
			"0,16 100,16 100,32 0,32"},
		{[]int{5, 5, 5, 5},
			"0,16 33,16 66,16 100,16",
			"0,16 33,16 66,16 100,16 100,32 0,32"},
		{[]int{3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5},
			"0,23 10,30 20,20 30,30 40,16 50,2 60,27 70,13 80,16 90,23 100,16",
			"0,23 10,30 20,20 30,30 40,16 50,2 60,27 70,13 80,16 90,23 100,16 100,32 0,32"},
	}
	for _, g := range golden {
		if got := SparklinePoints(g.series); got != g.points {
			t.Errorf("SparklinePoints(%v) = %q, want pre-refactor %q", g.series, got, g.points)
		}
		if got := SparklineArea(g.series); got != g.area {
			t.Errorf("SparklineArea(%v) = %q, want pre-refactor %q", g.series, got, g.area)
		}
		// Delegation sanity: scaling by the series' own range IS the unscaled render.
		lo, hi := seriesRange(g.series)
		if got := SparklinePointsScaled(g.series, lo, hi); got != g.points {
			t.Errorf("SparklinePointsScaled(%v, %d, %d) = %q, want %q", g.series, lo, hi, got, g.points)
		}
	}
}

func TestSparklinePointsScaled(t *testing.T) {
	cases := []struct {
		name   string
		series []int
		lo, hi int
		want   string
	}{
		{"empty", nil, 0, 10, ""},
		{"single sample stays a centered flat line", []int{7}, 0, 10, "0,16 100,16"},
		// shared scale: the same series renders lower/flatter under a larger hi
		// (own range would be 0,30 100,2; under hi=20 the 10 sits mid-box).
		{"larger shared hi flattens", []int{0, 10}, 0, 20, "0,30 100,16"},
		// values outside the range clamp to its edges (offline -1 samples under a
		// shared range computed without them).
		{"below-lo clamps to bottom", []int{-1, 10}, 0, 10, "0,30 100,2"},
		{"above-hi clamps to top", []int{5, 99}, 0, 10, "0,16 100,2"},
		// degenerate range renders the centered flat line, like a flat series.
		{"hi==lo is flat", []int{3, 4, 5}, 5, 5, "0,16 50,16 100,16"},
		{"hi<lo is flat", []int{3, 4, 5}, 9, 1, "0,16 50,16 100,16"},
	}
	for _, c := range cases {
		if got := SparklinePointsScaled(c.series, c.lo, c.hi); got != c.want {
			t.Errorf("%s: SparklinePointsScaled(%v, %d, %d) = %q, want %q", c.name, c.series, c.lo, c.hi, got, c.want)
		}
	}
	if got := SparklineAreaScaled([]int{0, 10}, 0, 20); got != "0,30 100,16 100,32 0,32" {
		t.Errorf("SparklineAreaScaled = %q, want closed polygon on the shared scale", got)
	}
	if got := SparklineAreaScaled(nil, 0, 20); got != "" {
		t.Errorf("empty SparklineAreaScaled = %q, want \"\"", got)
	}
}
