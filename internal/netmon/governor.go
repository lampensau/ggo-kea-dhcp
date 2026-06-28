package netmon

// The adaptive governor makes "monitoring is subordinate to Kea + the UI"
// structural rather than a setting. It does not trust a guessed CPU number; it
// asks the self-calibrating question "are we falling behind?" from two
// independent overflow signals plus a wire-rate leading indicator, and steps the
// monitor through fidelity levels with hysteresis so it cannot flap. Because the
// signals are relative to the actual hardware, a Pi 5 runs at full fidelity
// longer and a 2 GB Pi 4 sheds earlier - same code, no per-model tuning.

// govInputs are one tick's load signals. Only the two overflow counters drive
// level escalation - they are the direct "are we falling behind?" measure. Wire
// pps is deliberately NOT here: on a busy-but-healthy show LAN the in-kernel BPF
// keeps both counters ~0 while pps is enormous, so letting pps escalate would
// black out monitoring on exactly the networks the feature targets. pps is used
// only to suppress the promiscuous *sampling window* (the monitor's recomputeDuty),
// never to step the level.
type govInputs struct {
	tpDrops   uint32 // AF_PACKET PACKET_STATISTICS drops = socket-buffer overflow
	chanDrops uint32 // frame-channel drop-on-full count = userspace-pipeline overflow
}

// govConfig holds the breach thresholds and hysteresis counts. Defaults are set
// in defaultGovConfig and may be overridden from app_state.
type govConfig struct {
	dropHigh      uint32 // tp_drops/tick over which the socket buffer is overflowing
	chanDropHigh  uint32 // channel drops/tick over which the parse pipeline is behind
	ppsHigh       int    // wire pps over which we preemptively shed / suppress sampling
	stepDownAfter int    // sustained breach ticks required to shed (no flap on a spike)
	stepUpAfter   int    // sustained calm ticks required to recover
	cooldownTicks int    // ticks after any step before the next step-up is allowed
}

func defaultGovConfig() govConfig {
	return govConfig{
		dropHigh:      0, // any sustained socket-buffer drop means we're behind
		chanDropHigh:  0, // any sustained pipeline drop means we're behind
		ppsHigh:       50000,
		stepDownAfter: 2,
		stepUpAfter:   5,
		cooldownTicks: 5,
	}
}

// governor is the per-monitor load-shedding state machine.
type governor struct {
	cfg      govConfig
	level    Level
	breaches int
	calm     int
	cooldown int
}

func newGovernor(cfg govConfig) *governor { return &governor{cfg: cfg} }

func (g *governor) currentLevel() Level { return g.level }

// breach reports whether this tick's signals say we are falling behind. Either
// overflow counter firing is sufficient - they catch different bottlenecks (the
// socket buffer vs the parse pipeline). Wire pps is intentionally excluded (see
// govInputs): it gates the sampling window, not the level.
func (g *governor) breach(in govInputs) bool {
	return in.tpDrops > g.cfg.dropHigh || in.chanDrops > g.cfg.chanDropHigh
}

// observe folds one tick's signals into the level and returns the new level.
// Hysteresis: a sustained breach (stepDownAfter consecutive ticks) is required to
// step down, so a transient spike never sheds; a step-up requires sustained calm
// AND that the post-step cooldown has elapsed, so it cannot flap back up.
func (g *governor) observe(in govInputs) Level {
	if g.cooldown > 0 {
		g.cooldown--
	}
	if g.breach(in) {
		g.calm = 0
		g.breaches++
		if g.breaches >= g.cfg.stepDownAfter && g.level < LevelPaused {
			g.level++
			g.breaches = 0
			g.cooldown = g.cfg.cooldownTicks
		}
	} else {
		g.breaches = 0
		g.calm++
		if g.level > LevelFull && g.calm >= g.cfg.stepUpAfter && g.cooldown == 0 {
			g.level--
			g.calm = 0
			g.cooldown = g.cfg.cooldownTicks
		}
	}
	return g.level
}
