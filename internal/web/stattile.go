package web

import (
	"strconv"
	"strings"

	"ggo-kea-dhcp/internal/web/views"
)

// buildStatTiles assembles the four live dashboard stat tiles from the current
// lease/pool state plus the sampled trend series. The big values are live (this
// build); the sparklines are the always-on sampler's history.
func buildStatTiles(leaseCount int, pools []views.PoolRow, snap metricsSnapshot, ptp []views.PTPRow) []views.StatTileView {
	// (a) Active leases + churn over the sampled window.
	leasesT := views.StatTileView{
		Icon: "network", Label: "Active leases", Value: strconv.Itoa(leaseCount), Dot: "ok",
		Points: views.SparklinePoints(snap.LeaseCount), Area: views.SparklineArea(snap.LeaseCount),
		Tips: pointTips(snap.LeaseCount, ""),
	}
	if n := len(snap.LeaseCount); n > 1 {
		switch d := snap.LeaseCount[n-1] - snap.LeaseCount[0]; {
		case d > 0:
			leasesT.Delta, leasesT.DeltaDir = "+"+strconv.Itoa(d), "up"
		case d < 0:
			leasesT.Delta, leasesT.DeltaDir = strconv.Itoa(d), "down"
		}
	}

	// (b) Pool utilization % (leased / capacity across DHCP pools).
	pct := overallPoolUtil(pools)
	utilT := views.StatTileView{
		Icon: "gauge", Label: "Pool utilization", Value: strconv.Itoa(pct), Unit: "%", Dot: utilDot(pct),
		Points: views.SparklinePoints(snap.PoolPct), Area: views.SparklineArea(snap.PoolPct),
		Tips: pointTips(snap.PoolPct, "%"),
	}

	// (c) Uplink - reachability/latency; offline is neutral, never red.
	uplinkT := buildUplinkTile(snap.Uplink)

	// (d) Kea control-socket RTT ("lease processing").
	rttT := views.StatTileView{Icon: "clock", Label: "Lease processing", Dot: "ok", Points: views.SparklinePoints(snap.KeaRTT), Area: views.SparklineArea(snap.KeaRTT), Tips: pointTips(snap.KeaRTT, "ms")}
	if rtt := lastSample(snap.KeaRTT, -1); rtt < 0 {
		rttT.Value = "—"
	} else {
		rttT.Value, rttT.Unit = strconv.Itoa(rtt), "ms"
		if rtt > 250 {
			rttT.Dot = "warn"
		}
	}

	tiles := []views.StatTileView{leasesT, utilT, rttT, uplinkT}

	// (e) PTP grandmaster - only when one is actually observed (the panel-to-tile
	// promotion the operator asked for). The passive monitor cannot measure clock
	// offset, so the value is the lock status and the sparkline is the presence/
	// stability series (snap.Ptp), which surfaces a grandmaster that flaps.
	if len(ptp) > 0 {
		tiles = append(tiles, buildPTPTile(ptp[0], snap.Ptp))
	}
	return tiles
}

// buildPTPTile renders the PTP grandmaster stat tile. The value is the GM's
// advertised clock quality (clockClass -> "GPS-locked"/"Holdover"/"Free-run"/...),
// a real sync statistic rather than mere presence; the dot follows that quality.
// A degraded-presence signal (lost/contention, p.Severity "warn") still wins the
// dot so a flapping GM reads red even mid-quality. The sparkline is the clockClass
// trend, so a GM that loses its GPS lock (6 -> 7 -> 248) shows as a visible step.
func buildPTPTile(p views.PTPRow, series []int) views.StatTileView {
	val, dot := views.PTPQuality(p.ClockClass)
	if p.Severity == "warn" {
		dot = "warn" // presence trouble (lost/contention) overrides a nominally-fine class
	}
	return views.StatTileView{
		Icon: "radio-tower", Label: "PTP grandmaster", Value: val, Unit: p.Domain, Dot: dot,
		Points: views.SparklinePoints(series), Area: views.SparklineArea(series), Tips: ptpTips(series),
	}
}

// buildUplinkTile renders the uplink tile from the sampled latency series. A
// negative latest sample (the -1 sentinel) = offline/no-probe -> neutral
// "Offline" (never red; an isolated network is the expected state). Real latency
// lands in a later phase; until then every sample is -1 and the tile is Offline.
func buildUplinkTile(series []int) views.StatTileView {
	t := views.StatTileView{Icon: "globe", Label: "Uplink", EditHref: "/settings#wifi-uplink", EditLabel: "Configure WiFi uplink"}
	if last := lastSample(series, -1); last >= 0 {
		t.Value, t.Unit, t.Dot = strconv.Itoa(last), "ms", "ok"
		t.Points, t.Area = views.SparklinePoints(series), views.SparklineArea(series)
		t.Tips = uplinkTips(series)
	} else {
		t.Value = "Offline"
	}
	return t
}

// pointTips formats a value series into pipe-joined per-sample hover labels
// (oldest->newest) for the sparkline tooltip. "%" attaches with no space ("82%"),
// any other unit with a space ("12 ms"); an empty unit yields the bare number.
func pointTips(series []int, unit string) string {
	if len(series) == 0 {
		return ""
	}
	parts := make([]string, len(series))
	for i, v := range series {
		parts[i] = fmtTip(v, unit)
	}
	return strings.Join(parts, "|")
}

func fmtTip(v int, unit string) string {
	switch unit {
	case "":
		return strconv.Itoa(v)
	case "%":
		return strconv.Itoa(v) + "%"
	default:
		return strconv.Itoa(v) + " " + unit
	}
}

// uplinkTips maps the uplink latency series to hover labels, rendering the -1
// offline/no-probe sentinel as "offline" rather than a nonsensical "-1 ms".
func uplinkTips(series []int) string {
	parts := make([]string, len(series))
	for i, v := range series {
		if v < 0 {
			parts[i] = "offline"
		} else {
			parts[i] = strconv.Itoa(v) + " ms"
		}
	}
	return strings.Join(parts, "|")
}

// ptpTips maps the PTP clockClass series to hover labels: the -1 sentinel (no GM
// at that sample) reads "absent", every other value the quality label from
// PTPQuality. So hovering the trend tells the operator what the clock quality was
// at each point - "GPS-locked", "Holdover", "Free-run", "absent", ...
func ptpTips(series []int) string {
	parts := make([]string, len(series))
	for i, v := range series {
		if v < 0 {
			parts[i] = "absent"
		} else {
			label, _ := views.PTPQuality(v)
			parts[i] = label
		}
	}
	return strings.Join(parts, "|")
}

// overallPoolUtil is leased / capacity across the scope's DHCP pools, as a
// percentage clamped to 0-100 (elastic pools can momentarily read >100%).
func overallPoolUtil(pools []views.PoolRow) int {
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

// utilDot maps utilization % to the same thresholds as the pool-table meter
// (amber >=80, red >=95), so the tile and the table agree.
func utilDot(pct int) string {
	switch {
	case pct >= 95:
		return "err"
	case pct >= 80:
		return "warn"
	default:
		return "ok"
	}
}

// lastSample returns the newest value of a series, or def when empty.
func lastSample(series []int, def int) int {
	if len(series) == 0 {
		return def
	}
	return series[len(series)-1]
}
