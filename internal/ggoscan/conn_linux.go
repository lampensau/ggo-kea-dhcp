//go:build linux

package ggoscan

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// openConn binds the shared scan socket to :6464 with SO_BROADCAST (so the
// subnet-directed sweep can be sent) and SO_REUSEADDR.
func openConn() (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
					serr = e
					return
				}
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":6464")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
