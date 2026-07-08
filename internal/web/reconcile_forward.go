package web

import (
	"context"
	"time"

	"ggo-kea-dhcp/internal/kea"
)

// Thin Server -> reconciler forwarders. The lifecycle state machine lives on
// *reconciler (see reconciler.go); these keep the handler and background call
// sites that still speak to *Server compiling unchanged while the reconciler owns
// the logic. They carry no behavior of their own - each is a one-line delegate.

func (s *Server) beginReconcile() bool { return s.recon.beginReconcile() }

func (s *Server) endReconcile() { s.recon.endReconcile() }

func (s *Server) scheduleReconcileHeld(label string, delay time.Duration, mode ReconcileMode, profileID int) {
	s.recon.scheduleReconcileHeld(label, delay, mode, profileID)
}

func (s *Server) ReconcileApplianceState(mode ReconcileMode, targetProfileID int) error {
	return s.recon.ReconcileApplianceState(mode, targetProfileID)
}

func (s *Server) stopActiveMonitors() { s.recon.stopActiveMonitors() }

func (s *Server) runRecoveredAudited(name string, fn func()) {
	s.recon.runRecoveredAudited(name, fn)
}

func (s *Server) runRecoveredReconcile(name string, fn func()) {
	s.recon.runRecoveredReconcile(name, fn)
}

func (s *Server) baseRenderInput() kea.ProfileRenderInput { return s.recon.baseRenderInput() }

func (s *Server) renderKeaForScopes(scopes []ScopeConfig) (string, []string, error) {
	return s.recon.renderKeaForScopes(scopes)
}

func (s *Server) snapshotKeaConf(reason string) (string, error) {
	return s.recon.snapshotKeaConf(reason)
}

func (s *Server) writeAndReloadKea(ctx context.Context, configStr string) error {
	return s.recon.writeAndReloadKea(ctx, configStr)
}

func (s *Server) onboardingCIDR() string { return s.recon.onboardingCIDR() }

func (s *Server) softAPSettings() (ssid, pass string) { return s.recon.softAPSettings() }

func (s *Server) uplinkSettings() (enabled bool, ssid, pass string) {
	return s.recon.uplinkSettings()
}

func (s *Server) migrateUplinkToBoxLevel() { s.recon.migrateUplinkToBoxLevel() }

func (s *Server) leaseLifetime() int { return s.recon.leaseLifetime() }

func (s *Server) keaConfigForState(scopes []ScopeConfig) (string, error) {
	return s.recon.keaConfigForState(scopes)
}

func (s *Server) dhcpStoodDown() bool { return s.recon.dhcpStoodDown() }

func (s *Server) loadScopeConfigs(profileID int) ([]ScopeConfig, error) {
	return s.recon.loadScopeConfigs(profileID)
}

func (s *Server) remapReservationSubnets(ctx context.Context, scopes []ScopeConfig, mode ReconcileMode) {
	s.recon.remapReservationSubnets(ctx, scopes, mode)
}

func (s *Server) globalDHCPOptions() GlobalDHCPOptions { return s.recon.globalDHCPOptions() }
