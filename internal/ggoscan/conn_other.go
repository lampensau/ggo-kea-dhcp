//go:build !linux

package ggoscan

import (
	"errors"
	"net"
)

// openConn is unsupported off Linux (dev on another OS); the scanner stays disabled.
func openConn() (*net.UDPConn, error) {
	return nil, errors.New("ggoscan: unsupported platform")
}
