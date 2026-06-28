//go:build netmondebug

package netmon

// poison scribbles 0xDE over the frame buffer immediately after the full
// per-frame fan-out completes. Any detector that retained Frame.Data (instead of
// copying out the small fields it needs) reads poison on its next access, turning
// the aliasing-invariant violation into a deterministic, observation-window-
// independent failure. CI runs `go test -tags netmondebug -race ./internal/netmon/...`;
// production builds omit the tag (see poison.go - a no-op).
func poison(b []byte) {
	for i := range b {
		b[i] = 0xDE
	}
}
