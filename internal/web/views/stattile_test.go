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
