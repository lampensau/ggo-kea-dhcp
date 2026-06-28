package netmon

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// frameChanSize buffers accepted frames between the sniffer's read goroutine and
// the monitor. Because the kernel BPF drops the audio flood, only a handful of
// frames per second reach userspace, so this is generous; on overflow the read
// goroutine drops (never blocks - the drop-on-full discipline) and counts it.
const frameChanSize = 256

// errSnifferClosed signals the capture socket closed unexpectedly (a fault) - as
// opposed to a clean Stop, which the monitor detects via its quit channel.
var errSnifferClosed = errors.New("netmon: capture socket closed")

// capControl is the optional control surface a real capture socket exposes beyond
// Sniffer: the single promiscuous toggle, the dual overflow counters, and the
// fd/ifIndex for multicast joins. nopSniffer and FakeSniffer (without the test
// shim) do not implement it, so the monitor treats those capabilities as no-ops.
type capControl interface {
	setPromiscuous(on bool) error
	stats() (tpDrops, chanDrops uint32) // since last call; tp_drops is fetch-and-clear
	socketFD() int
	ifIndex() int
}

// afpacketSniffer is the real capture: one AF_PACKET/SOCK_RAW socket per
// interface with a kernel classic-BPF filter attached, read by a single
// goroutine. Accepted frames are copied into owned slices (cheap - the BPF means
// few fps) so they are safe to hand across the channel.
type afpacketSniffer struct {
	iface     string
	sock      int
	ifindex   int
	ch        chan Frame
	quit      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	chanDrops uint32 // atomic - incremented on drop-on-full
}

func (s *afpacketSniffer) Frames() <-chan Frame { return s.ch }

func (s *afpacketSniffer) Close() error {
	s.closeOnce.Do(func() {
		close(s.quit)          // readLoop returns within one SO_RCVTIMEO tick of seeing this
		_ = unix.Close(s.sock) // best-effort; closing an fd does NOT wake a blocked recvmsg,
		// so the receive timeout (set in openCapture) is what actually bounds the read
	})
	s.wg.Wait()
	return nil
}

func (s *afpacketSniffer) socketFD() int { return s.sock }
func (s *afpacketSniffer) ifIndex() int  { return s.ifindex }

func (s *afpacketSniffer) setPromiscuous(on bool) error {
	mreq := &unix.PacketMreq{Ifindex: int32(s.ifindex), Type: unix.PACKET_MR_PROMISC}
	op := unix.PACKET_ADD_MEMBERSHIP
	if !on {
		op = unix.PACKET_DROP_MEMBERSHIP
	}
	return unix.SetsockoptPacketMreq(s.sock, unix.SOL_PACKET, op, mreq)
}

func (s *afpacketSniffer) stats() (tpDrops, chanDrops uint32) {
	if st, err := unix.GetsockoptTpacketStats(s.sock, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
		tpDrops = st.Drops // PACKET_STATISTICS is fetch-and-clear: drops since last read
	}
	chanDrops = atomic.SwapUint32(&s.chanDrops, 0)
	return tpDrops, chanDrops
}

func (s *afpacketSniffer) readLoop() {
	defer s.wg.Done()
	defer close(s.ch)
	buf := make([]byte, 65536)
	// Out-of-band buffer for the per-frame PACKET_AUXDATA control message that
	// carries the VLAN tag the NIC stripped via RX-VLAN offload (see parseAuxVLAN).
	oob := make([]byte, unix.CmsgSpace(int(unsafe.Sizeof(unix.TpacketAuxdata{}))))
	for {
		select {
		case <-s.quit:
			return
		default:
		}
		n, oobn, _, _, err := unix.Recvmsg(s.sock, buf, oob, 0)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue // interrupted or recv-timeout: loop back and re-check quit
			}
			return // fd closed (Stop) or fatal - monitor sees the channel close
		}
		if n <= 0 {
			continue
		}
		vlan, vlanKnown := parseAuxVLAN(oob[:oobn])
		data := make([]byte, n) // owned copy (few fps post-BPF) - safe across channel
		copy(data, buf[:n])
		select {
		case s.ch <- Frame{Iface: s.iface, TS: time.Now(), Data: data, VLAN: vlan, VLANKnown: vlanKnown}:
		default:
			atomic.AddUint32(&s.chanDrops, 1) // drop-on-full: never queue/backpressure
		}
	}
}

// parseAuxVLAN recovers the VLAN id the NIC stripped via RX-VLAN offload from a
// frame's PACKET_AUXDATA control message. known is true whenever AUXDATA was
// delivered for the frame (so tag visibility works) - including an untagged frame,
// where vid is 0 - letting the VLAN-reality detector trust an empty result instead
// of reporting blindness. On a kernel that doesn't deliver AUXDATA it returns
// (0, false) and the detector falls back to the (likely tag-stripped) frame bytes.
func parseAuxVLAN(oob []byte) (vid int, known bool) {
	if len(oob) == 0 {
		return 0, false
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_PACKET || m.Header.Type != unix.PACKET_AUXDATA {
			continue
		}
		if len(m.Data) < int(unsafe.Sizeof(unix.TpacketAuxdata{})) {
			return 0, false
		}
		aux := (*unix.TpacketAuxdata)(unsafe.Pointer(&m.Data[0]))
		if aux.Status&unix.TP_STATUS_VLAN_VALID != 0 {
			return int(aux.Vlan_tci & 0x0fff), true
		}
		return 0, true // AUXDATA present, no stripped tag → untagged, visibility OK
	}
	return 0, false
}

// openCapture opens a non-promiscuous AF_PACKET socket on iface with the combined
// filter attached. On EPERM/EACCES (no CAP_NET_RAW) or a missing interface it logs
// [Dev Mode] and returns a nopSniffer - the same graceful bypass as the
// Commander's toolPresent path - so the appliance runs in the dev sandbox. The
// promisc argument is always false from the monitor: the monitor is the sole
// writer of the promiscuous bit (via setPromiscuous), so capture opens dark and
// the governor/duty-cycler turn it on.
func openCapture(iface string, promisc bool, filter []bpf.RawInstruction) (Sniffer, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		log.Printf("[Dev Mode] netmon: interface %s unavailable (%v) - capture disabled", iface, err)
		return newNopSniffer(), nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			log.Printf("[Dev Mode] netmon: AF_PACKET needs CAP_NET_RAW (%v) - capture disabled on %s", err, iface)
			return newNopSniffer(), nil
		}
		return nil, fmt.Errorf("netmon: open AF_PACKET on %s: %w", iface, err)
	}
	s := &afpacketSniffer{
		iface:   iface,
		sock:    fd,
		ifindex: ifi.Index,
		ch:      make(chan Frame, frameChanSize),
		quit:    make(chan struct{}),
	}
	// Attach a reject-all filter BEFORE bind so that in the window between socket()
	// (which is ETH_P_ALL on every interface) and bind-to-iface, no stray frame
	// from another interface - e.g. an LLDP from wlan0 - is queued and later
	// delivered mislabeled as this iface. The real filter is swapped in after bind.
	if err := attachFilter(fd, rejectAllFilter); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netmon: attach reject-all BPF on %s: %w", iface, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netmon: bind %s: %w", iface, err)
	}
	if len(filter) > 0 {
		if err := attachFilter(fd, filter); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("netmon: attach BPF on %s: %w", iface, err)
		}
	}
	// RX-VLAN offload strips the 802.1Q tag out of the frame bytes into packet
	// metadata, leaving the raw capture blind to VLANs. PACKET_AUXDATA makes the
	// kernel deliver the stripped tag as a per-frame control message (readLoop
	// recovers it via parseAuxVLAN). Best-effort: on a kernel without it the
	// VLAN-reality detector simply stays in its honest "tag visibility limited" state.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1)
	// Bound how long readLoop parks in Recvmsg so a clean Close() (which signals quit)
	// is honored within one tick even on a silent link. Closing the fd does NOT wake a
	// goroutine already blocked in recvmsg, so without this Stop() could hang until the
	// next packet arrived - which stalled a profile apply that stops the monitor first,
	// leaving the box wedged in CONFIGURING. The timeout never drops a real frame (it
	// only fires when the socket is idle).
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 250000})
	if promisc {
		_ = s.setPromiscuous(true)
	}
	s.wg.Add(1)
	go s.readLoop()
	return s, nil
}

// htons converts a uint16 to network byte order (AF_PACKET protocol fields).
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// attachFilter installs the assembled classic-BPF program via SO_ATTACH_FILTER.
func attachFilter(fd int, raw []bpf.RawInstruction) error {
	filt := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filt[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := &unix.SockFprog{Len: uint16(len(filt)), Filter: &filt[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
}
