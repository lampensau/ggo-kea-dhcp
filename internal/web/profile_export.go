package web

// ProfileExport is the portable JSON representation of a profile. It now serves a
// single internal use: the Edit Configuration prefill, where activeProfilePrefill
// marshals the active profile into the wizard's #ggo-prefill island and the client
// rebuilds the scope cards from it (ggoApplyImported). It round-trips through
// ScopeConfig. The user-facing profile Export/Import (Settings download + wizard
// buttons) was removed in favour of the full-appliance Backup.
type ProfileExport struct {
	Name   string        `json:"name"`
	Scopes []ScopeConfig `json:"scopes"`
}
