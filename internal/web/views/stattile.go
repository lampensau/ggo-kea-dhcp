package views

import (
	"strconv"
	"strings"
)

// StatTileView is one Grafana-style live stat tile: a labelled metric value with
// an inline-SVG sparkline of its recent trend. Points is precomputed by the build
// (SparklinePoints) so the templ stays logic-free and the SSE fragment matches
// first paint byte-for-byte. Dot/Unit/Delta are semantic, not decorative.
type StatTileView struct {
	Icon     string // @Icon glyph
	Label    string
	Value    string // big value, already formatted
	Unit     string // optional suffix ("ms", "%")
	Dot      string // "ok"/"warn"/"err"/"" - also the sparkline stroke severity
	Delta    string // optional churn ("+3")
	DeltaDir string // "up"/"down"/""
	Points   string // SVG polyline points for the trend line ("" = no sparkline)
	Area     string // SVG polygon points for the filled area under the line
	Tips     string // per-sample hover labels (oldest->newest, pipe-joined) for the tooltip
	// EditHref, when set, renders a small edit affordance in the tile corner linking
	// somewhere to configure this metric (e.g. the uplink tile -> Settings WiFi
	// uplink). EditLabel is its accessible name.
	EditHref  string
	EditLabel string
}

// sparkSummary is the screen-reader text for a tile's sparkline (which is itself
// aria-hidden decorative SVG): the metric's oldest and newest sampled values, so a
// non-visual user gets the trend the chart conveys. Empty when there are no tips.
func sparkSummary(t StatTileView) string {
	if t.Tips == "" {
		return ""
	}
	tips := strings.Split(t.Tips, "|")
	first, last := tips[0], tips[len(tips)-1]
	return t.Label + " trend: " + first + " to " + last
}

const sparkW, sparkH = 100, 32

// SparklinePoints maps an int time series to an SVG <polyline> "points" string in
// a fixed 100x32 viewBox (oldest left, newest right). It returns "" for an empty
// series; a single sample or a flat series renders a centered horizontal line.
// Coordinates are always within the box (the value range is normalized), so a
// series containing negatives still yields valid non-negative coordinates.
func SparklinePoints(series []int) string {
	lo, hi := seriesRange(series)
	return SparklinePointsScaled(series, lo, hi)
}

// SparklinePointsScaled is SparklinePoints against a caller-supplied lo/hi value
// range, so tiles sharing a unit (the two millisecond tiles) can render on one
// vertical scale and stay visually comparable. Values outside the range clamp to
// its edges (a shared range computed ignoring -1 sentinels must still place those
// samples inside the box); a degenerate range (hi <= lo) renders the centered
// flat line, same as a flat series.
func SparklinePointsScaled(series []int, lo, hi int) string {
	if len(series) == 0 {
		return ""
	}
	const pad = 2
	mid := sparkH / 2
	if len(series) == 1 {
		return "0," + strconv.Itoa(mid) + " " + strconv.Itoa(sparkW) + "," + strconv.Itoa(mid)
	}
	n := len(series)
	var b strings.Builder
	for i, v := range series {
		x := i * sparkW / (n - 1)
		y := mid
		if hi > lo {
			if v < lo {
				v = lo
			}
			if v > hi {
				v = hi
			}
			// invert: hi -> top (pad), lo -> bottom (h-pad)
			y = (sparkH - pad) - (v-lo)*(sparkH-2*pad)/(hi-lo)
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.Itoa(x))
		b.WriteByte(',')
		b.WriteString(strconv.Itoa(y))
	}
	return b.String()
}

// SparklineArea returns the polygon points for the filled area under the trend
// line: the line points plus the two baseline corners (bottom-right, bottom-left),
// which the <polygon> auto-closes back to the first point. "" for an empty series.
func SparklineArea(series []int) string {
	lo, hi := seriesRange(series)
	return SparklineAreaScaled(series, lo, hi)
}

// SparklineAreaScaled is SparklineArea against a caller-supplied lo/hi range
// (see SparklinePointsScaled).
func SparklineAreaScaled(series []int, lo, hi int) string {
	line := SparklinePointsScaled(series, lo, hi)
	if line == "" {
		return ""
	}
	return line + " " + strconv.Itoa(sparkW) + "," + strconv.Itoa(sparkH) + " 0," + strconv.Itoa(sparkH)
}

// seriesRange is the min/max of a series (0,0 when empty); the per-series
// normalization the unscaled variants delegate with.
func seriesRange(series []int) (lo, hi int) {
	if len(series) == 0 {
		return 0, 0
	}
	lo, hi = series[0], series[0]
	for _, v := range series {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	return lo, hi
}
