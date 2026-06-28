package netmon

import "time"

const (
	// defaultStormPPS is the rx-packets-per-second over which the wire is treated
	// as storming (overridable via netmon_storm_pps).
	defaultStormPPS = 5000
	// STP topology-change churn: this many TCN/TC BPDUs within the window means
	// the spanning tree is unstable (a flapping link reconverging repeatedly).
	stpChurnWindow    = 30 * time.Second
	stpChurnThreshold = 5
)

// macSTP is the IEEE 802.1D spanning-tree BPDU destination.
var macSTP = [6]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}

// rxCounterFunc reads the interface's cumulative rx-packets counter (from
// /sys/class/net/<iface>/statistics/rx_packets). ok is false when the counter is
// unavailable (dev sandbox / no interface), so the storm-volume signal simply
// goes quiet rather than firing on garbage.
type rxCounterFunc func() (rxPackets uint64, ok bool)

// stormDetector watches two link-health failure modes cheaply:
//   - Broadcast/multicast storm volume, read as rx-packet counter deltas per tick
//     from sysfs - NOT per-packet capture - so CPU stays flat under an actual
//     storm (the whole point: you cannot afford to parse a storm packet-by-packet).
//   - STP topology churn, counted from the low-rate BPDU stream (TCN BPDUs and
//     config BPDUs with the topology-change flag).
type stormDetector struct {
	iface     string
	threshold int
	rx        rxCounterFunc

	lastPkts uint64
	lastTick time.Time
	haveLast bool
	curPPS   int
	highRuns int  // consecutive ticks over threshold (debounce)
	storming bool // confirmed storm state

	tcnTimes     []time.Time
	churning     bool
	framesFrozen bool // set by the monitor at L2/L3: freeze the frame-fed STP half
}

// setFramesDropped tells the storm detector whether the monitor is dropping
// frames (>= LevelCountersOnly). Storm is hybrid - its pps half is counter-fed
// (keeps running at L2) but its STP/BPDU-churn half is frame-fed, so when frames
// are dropped the churn half must freeze, exactly like the N1 presence freeze;
// otherwise a blind L2 stretch drains tcnTimes and emits a false "STP stabilized"
// (cleared because we stopped looking, not because the tree settled).
func (d *stormDetector) setFramesDropped(dropping bool) { d.framesFrozen = dropping }

func newStormDetector(iface string, threshold int, rx rxCounterFunc) *stormDetector {
	if threshold <= 0 {
		threshold = defaultStormPPS
	}
	return &stormDetector{iface: iface, threshold: threshold, rx: rx}
}

func (d *stormDetector) Consume(f Frame, now time.Time) {
	dm, ok := dstMAC(f.Data)
	if !ok || dm != macSTP {
		return
	}
	// 802.3 LLC (3 bytes) then BPDU: protocolID(2) version(1) type(1) flags(1).
	const bpduOff = ethHdrLen + 3
	if bpduOff+4 >= len(f.Data) {
		return
	}
	bpduType := f.Data[bpduOff+3]
	flags := f.Data[bpduOff+4]
	if bpduType == 0x80 || (bpduType == 0x00 && flags&0x01 != 0) { // TCN or TC flag
		d.tcnTimes = append(d.tcnTimes, now)
	}
}

func (d *stormDetector) Tick(now time.Time) []Event {
	var events []Event

	// --- storm volume from counter deltas ---
	// curPPS goes to 0 (signal quiet) on a failed read or a counter reset, rather
	// than latching its last value - otherwise a transient sysfs read failure
	// during a storm would leave a phantom storm that never clears (the clear path
	// needs curPPS < threshold). [M5]
	if d.rx != nil {
		cur, ok := d.rx()
		switch {
		case !ok:
			d.curPPS = 0 // counter unavailable → quiet, never latch
			d.haveLast = false
		case d.haveLast && cur >= d.lastPkts:
			if dt := now.Sub(d.lastTick).Seconds(); dt > 0 {
				d.curPPS = int(float64(cur-d.lastPkts) / dt)
			}
			d.lastPkts = cur
			d.lastTick = now
		default: // first sample, or counter reset (cur < lastPkts) → re-baseline
			d.curPPS = 0
			d.lastPkts = cur
			d.lastTick = now
			d.haveLast = true
		}
	}
	if d.curPPS >= d.threshold {
		d.highRuns++
	} else {
		d.highRuns = 0
	}
	switch {
	case !d.storming && d.highRuns >= 2: // sustained → confirm
		d.storming = true
		events = append(events, Event{
			Action:   "Broadcast storm detected",
			Target:   d.iface,
			Before:   "stable",
			After:    itoa(d.curPPS) + " pps",
			Severity: SevWarn,
		})
	case d.storming && d.curPPS < d.threshold:
		d.storming = false
		events = append(events, Event{
			Action:   "Broadcast storm cleared",
			Target:   d.iface,
			Before:   "storming",
			After:    itoa(d.curPPS) + " pps",
			Severity: SevInfo,
		})
	}

	// --- STP churn from BPDU counts (frame-fed: frozen while frames are dropped) ---
	if d.framesFrozen {
		return events // pps half already evaluated above; don't touch the churn state
	}
	d.tcnTimes = pruneBefore(d.tcnTimes, now.Add(-stpChurnWindow))
	churn := len(d.tcnTimes) >= stpChurnThreshold
	switch {
	case churn && !d.churning:
		d.churning = true
		events = append(events, Event{
			Action:   "STP topology churn",
			Target:   d.iface,
			Before:   "stable",
			After:    itoa(len(d.tcnTimes)) + " changes/" + itoa(int(stpChurnWindow.Seconds())) + "s",
			Severity: SevWarn,
		})
	case !churn && d.churning:
		d.churning = false
		events = append(events, Event{
			Action:   "STP topology stabilized",
			Target:   d.iface,
			Before:   "churning",
			After:    "stable",
			Severity: SevInfo,
		})
	}

	return events
}

func (d *stormDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "storm", Subject: d.iface}
	switch {
	case d.storming:
		s.Severity = SevWarn
		s.Text = "Broadcast storm - " + itoa(d.curPPS) + " pps"
		s.Fields = map[string]string{"pps": itoa(d.curPPS)}
	case d.churning:
		s.Severity = SevWarn
		s.Text = "STP topology churn"
		s.Fields = map[string]string{"changes": itoa(len(d.tcnTimes))}
	default:
		s.Severity = SevOK
		s.Text = "No broadcast storm"
		s.Fields = map[string]string{"pps": itoa(d.curPPS)}
	}
	return s
}
