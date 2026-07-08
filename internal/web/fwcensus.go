package web

import "sync"

// fwCensus owns the Green-GO firmware-mismatch audit state. scopes is the set of
// greengo-preset scopes the scanner targets (set when the scan spec list is
// rebuilt); lastSig is the last audited mismatch census ("" = uniform), so
// attachFirmware audits transitions once, not on every render. The compare-and-set
// in transition is serialized under mu because attachFirmware runs from concurrent
// render paths.
type fwCensus struct {
	mu      sync.Mutex
	scopes  []fwScope
	lastSig string
}

func newFwCensus() *fwCensus { return &fwCensus{} }

// setScopes records the scopes the scanner currently targets.
func (c *fwCensus) setScopes(scopes []fwScope) {
	c.mu.Lock()
	c.scopes = scopes
	c.mu.Unlock()
}

// snapshotScopes returns the current target scopes.
func (c *fwCensus) snapshotScopes() []fwScope {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scopes
}

// transition compare-and-sets the audited census signature, returning the prior
// signature and whether it changed (false = same census, caller stays silent).
func (c *fwCensus) transition(sig string) (prev string, changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev = c.lastSig
	if sig == prev {
		return prev, false
	}
	c.lastSig = sig
	return prev, true
}
