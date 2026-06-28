package netmon

import "time"

// idleAbsence is how long an interface must receive zero new rx packets before the
// monitor warns it is silent. A configured VLAN carrying no traffic for this long is
// almost always a trunk port not passing the tag (or nothing plugged in) - even a
// quiet segment emits ARP/broadcast well inside this window.
const idleAbsence = 5 * time.Minute

// idleDetector warns when an interface sees no traffic at all for idleAbsence. It is
// counter-fed (rx-packets from sysfs, like stormDetector), so it costs nothing and
// keeps working when frame capture is shed under load. A silent configured VLAN is
// the operator's signal: the scope exists but the wire is dead.
type idleDetector struct {
	iface   string
	absence time.Duration
	rx      rxCounterFunc

	lastPkts    uint64
	haveLast    bool
	started     time.Time // first observed tick (grace before the first warning)
	lastTraffic time.Time // last tick at which rx increased
	idle        bool      // confirmed-silent state (warning latched)
}

func newIdleDetector(iface string, rx rxCounterFunc) *idleDetector {
	return &idleDetector{iface: iface, absence: idleAbsence, rx: rx}
}

func (d *idleDetector) Consume(Frame, time.Time) {}

func (d *idleDetector) Tick(now time.Time) []Event {
	if d.rx == nil {
		return nil
	}
	cur, ok := d.rx()
	if !ok {
		return nil // counter unavailable (dev sandbox) - stay quiet, never warn
	}
	if d.started.IsZero() {
		d.started = now
	}
	switch {
	case !d.haveLast:
		d.haveLast, d.lastPkts, d.lastTraffic = true, cur, now
	case cur != d.lastPkts: // any change (incl. counter reset) counts as traffic
		d.lastPkts, d.lastTraffic = cur, now
	}
	// Require a full absence window of observation before the first warning, so a
	// freshly-started monitor doesn't flap "no traffic" before a frame can arrive.
	if now.Sub(d.started) < d.absence {
		return nil
	}
	silent := now.Sub(d.lastTraffic) >= d.absence
	switch {
	case silent && !d.idle:
		d.idle = true
		return []Event{{
			Action:   "No traffic on interface",
			Target:   d.iface,
			Before:   "active",
			After:    "silent for " + itoa(int(d.absence.Minutes())) + "m+",
			Severity: SevWarn,
		}}
	case !silent && d.idle:
		d.idle = false
		return []Event{{
			Action:   "Traffic resumed on interface",
			Target:   d.iface,
			Before:   "silent",
			After:    "active",
			Severity: SevInfo,
		}}
	}
	return nil
}

func (d *idleDetector) Snapshot() DetectorSnapshot {
	s := DetectorSnapshot{Kind: "idle", Subject: d.iface}
	if d.idle {
		s.Severity = SevWarn
		s.Text = "No network activity (" + itoa(int(d.absence.Minutes())) + "m+)"
		return s
	}
	s.Severity = SevOK
	s.Text = "Active network traffic"
	return s
}
