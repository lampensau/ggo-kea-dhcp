package appliance

import (
	"fmt"

	"ggo-kea-dhcp/internal/kea"
)

// DHCPStandDownKey is the app_state flag that, while "1", holds the appliance in a
// deliberate DHCP stand-down: it stays in the ACTIVE lifecycle but serves no
// address (a holdoff Kea config). Persisted so a reboot/reconcile mid-conflict
// does not silently resume serving - only an explicit operator Resume clears it.
const DHCPStandDownKey = "dhcp_standdown"

// DHCPStoodDown reports whether the operator has stood DHCP down.
func (r *Reconciler) DHCPStoodDown() bool {
	v, _ := r.sqlite.GetState(DHCPStandDownKey)
	return v == "1"
}

// renderHoldoffConfig renders the stand-down Kea config for the active profile's
// served interfaces: Kea stays reachable but serves no subnet on any of them.
func (r *Reconciler) renderHoldoffConfig(scopes []ScopeConfig) (string, error) {
	ifaces := make([]string, 0, len(scopes))
	seen := map[string]bool{}
	for _, sc := range scopes {
		iface := "eth0"
		if sc.VlanID != 0 {
			iface = fmt.Sprintf("eth0.%d", sc.VlanID)
		}
		if seen[iface] {
			continue
		}
		seen[iface] = true
		ifaces = append(ifaces, iface)
	}
	return kea.RenderHoldoff(kea.HoldoffInput{
		Interfaces:    ifaces,
		KeaSecretPath: r.cfg.KeaSecretPath,
	})
}

// KeaConfigForState renders the Kea config the current lifecycle intends: the
// holdoff (no subnets) when DHCP is stood down, else the active profile config.
// reconcileActive and the stand-down/resume handlers both go through here, so a
// reboot honors a persisted stand-down instead of silently resuming service.
func (r *Reconciler) KeaConfigForState(scopes []ScopeConfig) (string, error) {
	if r.DHCPStoodDown() {
		return r.renderHoldoffConfig(scopes)
	}
	cfg, _, err := r.RenderKeaForScopes(scopes)
	return cfg, err
}
