package appliance

import (
	"encoding/json"
	"log"
)

// GlobalDHCPOptionsFor returns the site-wide DHCP option defaults (every scope inherits
// them unless it overrides per-scope). When the key is unset it migrates a previously
// chosen legacy uplink_dns resolver into the global DNS default - the bare 1.1.1.1
// default is NOT migrated, since a global default must be an explicit operator choice.
func (r *Reconciler) GlobalDHCPOptionsFor() GlobalDHCPOptions {
	var g GlobalDHCPOptions
	if v, _ := r.sqlite.GetState("global_dhcp_options"); v != "" {
		if err := json.Unmarshal([]byte(v), &g); err != nil {
			log.Printf("[settings] malformed global_dhcp_options - ignoring: %v", err)
			return GlobalDHCPOptions{}
		}
		return g
	}
	if v, _ := r.sqlite.GetState("uplink_dns"); v != "" && v != "disabled" {
		g.DNS = v
	}
	return g
}

// ActiveProfileUplink returns the active profile's id and its uplink config. The
// uplink is conceptually one per box; it is persisted on every scope row, so we
// return the first enabled scope's uplink (else the first scope's). ok is false
// when there is no active profile or it has no scopes.
func (r *Reconciler) ActiveProfileUplink() (profileID int, cfg UplinkConfig, ok bool) {
	if err := r.sqlite.QueryRow("SELECT id FROM profiles WHERE active = 1 LIMIT 1").Scan(&profileID); err != nil {
		return 0, UplinkConfig{}, false
	}
	scopes, err := r.LoadScopeConfigs(profileID)
	if err != nil || len(scopes) == 0 {
		return profileID, UplinkConfig{}, false
	}
	for _, sc := range scopes {
		if sc.Uplink.Enabled {
			return profileID, sc.Uplink, true
		}
	}
	return profileID, scopes[0].Uplink, true
}
