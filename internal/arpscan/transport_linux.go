//go:build linux

package arpscan

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// afpacketTransport is the real send/receive path: one AF_PACKET/SOCK_RAW socket per
// interface with an ARP-only classic-BPF filter, so the receive loop sees only ARP and
// the send path writes raw L2 frames. The socket is read+write (unlike netmon's capture,
// which only reads) because presence requires actively eliciting replies.
type afpacketTransport struct {
	sock      int
	ifindex   int
	closeOnce sync.Once
}

// OpenAFPacket opens the probe socket for a served interface. EPERM (no CAP_NET_RAW) or a
// missing interface returns an error; Prober.Start logs and skips that iface, so the box
// still runs (presence just stays unavailable, like netmon in the dev sandbox).
func OpenAFPacket(spec Spec) (Transport, error) {
	ifi, err := net.InterfaceByName(spec.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", spec.Iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket on %s: %w", spec.Iface, err) // EPERM = no CAP_NET_RAW
	}
	if err := attachARPFilter(fd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("attach ARP BPF on %s: %w", spec.Iface, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", spec.Iface, err)
	}
	// Receive timeout so Recvfrom returns periodically and recvLoop can honor quit:
	// closing the fd does NOT wake a goroutine already blocked in recvfrom, so without
	// this Stop() could hang on a silent link until the next ARP frame arrived.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 250000})
	return &afpacketTransport{sock: fd, ifindex: ifi.Index}, nil
}

func (t *afpacketTransport) Send(frame []byte) error {
	return unix.Sendto(t.sock, frame, 0, &unix.SockaddrLinklayer{Ifindex: t.ifindex})
}

// Receive returns (frame, true) for an ARP frame, (nil, true) on a recv-timeout or
// EINTR so the caller loops and re-checks quit, and (nil, false) only when the socket
// is closed/faulted (ending recvLoop).
func (t *afpacketTransport) Receive() ([]byte, bool) {
	buf := make([]byte, 1514) // a max untagged Ethernet frame; ARP is far smaller
	n, _, err := unix.Recvfrom(t.sock, buf, 0)
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
		return nil, true // idle tick: no frame, but the socket is alive - keep looping
	}
	if err != nil || n <= 0 {
		return nil, false // fd closed by Close (Stop) or a fatal error - end recvLoop
	}
	return buf[:n], true
}

func (t *afpacketTransport) Close() error {
	// Best-effort; closing the fd does NOT wake a blocked recvfrom, so the receive
	// timeout (set in OpenAFPacket) is what actually bounds the read and lets quit win.
	t.closeOnce.Do(func() { _ = unix.Close(t.sock) })
	return nil
}

// htons converts a uint16 to network byte order (AF_PACKET protocol fields).
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// attachARPFilter installs a minimal classic-BPF that accepts only ethertype-ARP frames
// (the served-scope socket sees untagged frames, so ARP sits at the fixed offset 12).
func attachARPFilter(fd int) error {
	raw, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                                            // ethertype
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeARP, SkipTrue: 0, SkipFalse: 1}, // ARP → accept
		bpf.RetConstant{Val: 0x40000},                                                 // accept whole frame
		bpf.RetConstant{Val: 0},                                                       // reject
	})
	if err != nil {
		return err
	}
	filt := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filt[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := &unix.SockFprog{Len: uint16(len(filt)), Filter: &filt[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
}
