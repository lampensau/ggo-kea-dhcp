//go:build !netmondebug

package netmon

// poison is a no-op in production builds (zero overhead). The netmondebug build
// (poison_debug.go) replaces it with a buffer-scribbler that turns a retained-
// slice bug into a deterministic failure under `go test -tags netmondebug -race`.
func poison(_ []byte) {}
