//go:build !linux

package arpscan

import "errors"

// OpenAFPacket is Linux-only (the appliance runs on a Raspberry Pi). This stub lets the
// package and its tests build on a dev workstation; the real prober only runs on the Pi,
// and tests inject a fake transport via newProberWithOpen.
func OpenAFPacket(Spec) (Transport, error) {
	return nil, errors.New("arpscan: AF_PACKET probing is Linux-only")
}
