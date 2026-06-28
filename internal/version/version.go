// Package version is the single source of truth for the appliance's product
// version. It is bumped manually on a release. Everything that needs to show a
// version (the startup log, the Settings page) reads Number from here - there is
// no other product-version definition in the tree (AssetVer is a cache-bust hash
// and PRAGMA user_version is the DB-migration counter, both unrelated).
package version

// Number is the displayed product version. Bump it on a release.
const Number = "1.1.1"

// Name is the application's canonical short name - the binary, the systemd unit,
// the Go module path, and the user-facing identity (startup log, audit "STARTUP"
// target).
const Name = "ggo-kea-dhcp"
