package web

import (
	"context"

	"ggo-kea-dhcp/internal/appliance"
	"ggo-kea-dhcp/internal/db"
)

// The lifecycle state machine lives in internal/appliance. These aliases and thin
// wrappers keep the ~15 web files that name its types, and the many that call its
// leaf helpers, compiling unchanged across the new package boundary. They are a
// migration seam, not an abstraction: burn them down as the call sites are touched.

type (
	ScopeConfig       = appliance.ScopeConfig
	ScopeServices     = appliance.ScopeServices
	ScopeOption       = appliance.ScopeOption
	GlobalDHCPOptions = appliance.GlobalDHCPOptions
	PoolPlan          = appliance.PoolPlan
	PoolPlanEntry     = appliance.PoolPlanEntry
	DeviceCounts      = appliance.DeviceCounts
	UplinkConfig      = appliance.UplinkConfig
	ReconcileMode     = appliance.ReconcileMode
	MonitorSet        = appliance.MonitorSet
	PresenceProber    = appliance.PresenceProber
	DeviceScanner     = appliance.DeviceScanner
	RogueProber       = appliance.RogueProber
	portIdent         = appliance.PortIdent
)

const (
	ModeConverge = appliance.ModeConverge
	ModeApply    = appliance.ModeApply

	PoolKindFixed   = appliance.PoolKindFixed
	PoolKindElastic = appliance.PoolKindElastic
	PoolKindReserve = appliance.PoolKindReserve
)

// Leaf helpers, wrapped so their many web call sites stay as they were.
func normalizeMAC(mac string) string      { return appliance.NormalizeMAC(mac) }
func colonHex(b []byte) string            { return appliance.ColonHex(b) }
func capacityOf(lo, hi uint32) int        { return appliance.CapacityOf(lo, hi) }
func bytesToPortIdentity(b []byte) string { return appliance.BytesToPortIdentity(b) }
func decodePortIdentity(clientID string) (portIdent, bool) {
	return appliance.DecodePortIdentity(clientID)
}
func portIdentFromFlex(flex []byte) portIdent { return appliance.PortIdentFromFlex(flex) }
func seedDefaultPlan(sc ScopeConfig) PoolPlan { return appliance.SeedDefaultPlan(sc) }
func uplinkState(enabled bool, ssid, pass string) map[string]string {
	return appliance.UplinkState(enabled, ssid, pass)
}

func flexIDToBytes(id string) []byte { return appliance.FlexIDToBytes(id) }

func runRecovered(name string, fn func()) { appliance.RunRecovered(name, fn) }
func flatPlan() PoolPlan                  { return appliance.FlatPlan() }
func seedPlan(sc ScopeConfig) PoolPlan    { return appliance.SeedPlan(sc) }

func parseScopeServices(gateway, dns, lease, localDNS string, optNames, optData []string) (ScopeServices, error) {
	return appliance.ParseScopeServices(gateway, dns, lease, localDNS, optNames, optData)
}

const defaultSizePreset = appliance.DefaultSizePreset

var goSizePresets = appliance.GoSizePresets

var _ = context.Background
var _ db.HostReservation
