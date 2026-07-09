package web

import (
	"context"
	"time"
)

// serverHooks is the Server's side of appliance.Hooks: the reconciler's only path
// back into the web layer, and so the only place the SSE hub, the DNS zone, the
// update subsystem and the monitors are reachable from a converge.
type serverHooks struct{ s *Server }

func (h serverHooks) AnnounceUplink(down bool, detail string) {
	h.s.health.setUplinkDown(down, detail)
	h.s.publishBackendAlert()
}

func (h serverHooks) PrimeZone() { h.s.primeDNSZone() }

func (h serverHooks) KickUpdate() { h.s.kickUpdateCheck() }

func (h serverHooks) StartNetmon(scopes []ScopeConfig) { h.s.startNetmon(scopes) }

func (h serverHooks) StartArpProber(scopes []ScopeConfig) { h.s.startArpProber(scopes) }

func (h serverHooks) StartGgoScan(scopes []ScopeConfig) { h.s.startGgoScan(scopes) }

// Thin Server -> Reconciler forwarders. The lifecycle state machine lives in
// internal/appliance; these keep the handler and background call sites that speak to
// *Server compiling unchanged while the appliance owns the logic. They carry no
// behavior of their own - each is a one-line delegate.
//
// Only names with several callers (or callers in tests) earn a forwarder; a lone
// call site says s.recon.X() outright rather than paying for one here.

func (s *Server) beginReconcile() bool { return s.recon.BeginReconcile() }

func (s *Server) endReconcile() { s.recon.EndReconcile() }

func (s *Server) scheduleReconcileHeld(label string, delay time.Duration, mode ReconcileMode, profileID int) {
	s.recon.ScheduleReconcileHeld(label, delay, mode, profileID)
}

func (s *Server) ReconcileApplianceState(mode ReconcileMode, targetProfileID int) error {
	return s.recon.ReconcileApplianceState(mode, targetProfileID)
}

func (s *Server) stopActiveMonitors() { s.recon.StopActiveMonitors() }

func (s *Server) runRecoveredAudited(name string, fn func()) {
	s.recon.RunRecoveredAudited(name, fn)
}

func (s *Server) runRecoveredReconcile(name string, fn func()) {
	s.recon.RunRecoveredReconcile(name, fn)
}

func (s *Server) onboardingCIDR() string { return s.recon.OnboardingCIDR() }

func (s *Server) uplinkSettings() (enabled bool, ssid, pass string) {
	return s.recon.UplinkSettings()
}

func (s *Server) leaseLifetime() int { return s.recon.LeaseLifetime() }

func (s *Server) keaConfigForState(scopes []ScopeConfig) (string, error) {
	return s.recon.KeaConfigForState(scopes)
}

func (s *Server) dhcpStoodDown() bool { return s.recon.DHCPStoodDown() }

func (s *Server) loadScopeConfigs(profileID int) ([]ScopeConfig, error) {
	return s.recon.LoadScopeConfigs(profileID)
}

func (s *Server) remapReservationSubnets(ctx context.Context, scopes []ScopeConfig, mode ReconcileMode) {
	s.recon.RemapReservationSubnets(ctx, scopes, mode)
}
