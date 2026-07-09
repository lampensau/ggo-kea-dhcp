package web

import (
	"context"
	"time"
)

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
