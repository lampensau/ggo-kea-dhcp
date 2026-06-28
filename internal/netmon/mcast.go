package netmon

import "golang.org/x/sys/unix"

// Multicast strategy (discover-then-join, cheaper than holding promiscuous):
// known/derivable groups are joined directly - a benign *receiver* action (not a
// querier; harmless extra joiner; no effect on audio). PTP and mDNS groups are
// fixed and joined up front; sACN groups are per-universe and joined as universes
// are discovered during the promiscuous duty-cycle sample. With the NIC's hardware
// multicast filter, only joined groups + broadcast reach the kernel, far cheaper
// than holding promiscuous against the full audio flood.

// knownGroups are the multicast groups we can join directly without discovery:
// PTP (IEEE 1588 default + pdelay) and mDNS. sACN groups are per-universe and are
// derived (sacnUniverseGroup) as universes are discovered.
var knownGroups = [][4]byte{
	{224, 0, 1, 129}, // PTP primary
	{224, 0, 1, 130},
	{224, 0, 1, 131},
	{224, 0, 1, 132},
	{224, 0, 0, 107}, // PTP pdelay
	{224, 0, 0, 251}, // mDNS
}

// knownMACs are L2 control-plane multicast groups whose dst MAC is NOT derived
// from an IPv4 group, so they need a raw-MAC join. Without joining these the NIC
// hardware filter drops them before our BPF runs (they reach Wireshark only
// because it sets promiscuous), starving the LLDP/CDP and STP-churn detectors.
// Low-rate and always-on, so joined up front like knownGroups (no promiscuous).
var knownMACs = [][6]byte{
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}, // LLDP (nearest bridge)
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}, // LLDP (nearest non-TPMR bridge)
	{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}, // CDP
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}, // STP/BPDU
}

// sacnUniverseGroup derives the E1.31 multicast group for a universe:
// 239.255.<hi>.<lo>, where the last two octets are the universe number.
func sacnUniverseGroup(universe uint16) [4]byte {
	return [4]byte{239, 255, byte(universe >> 8), byte(universe)}
}

// sacnUniverseOf returns the E1.31 universe carried by an sACN data frame, used
// to join that universe's multicast group during discovery.
func sacnUniverseOf(f Frame) (uint16, bool) {
	et, off, _, ok := etherInfo(f.Data)
	if !ok || et != etherTypeIPv4 {
		return 0, false
	}
	proto, _, _, l4, ok := ipv4Info(f.Data, off)
	if !ok || proto != ipProtoUDP {
		return 0, false
	}
	_, dport, payload, ok := udpPorts(f.Data, l4)
	if !ok || dport != sacnPort {
		return 0, false
	}
	p := f.Data[payload:]
	if len(p) < 115 {
		return 0, false
	}
	return be16(p, 113), true
}

// multicastJoiner owns the IGMP group memberships on one capture socket. It is
// the only thing that joins/leaves groups, and join is idempotent so the
// discover-then-join loop can call it freely.
type multicastJoiner struct {
	fd        int
	ifIndex   int
	joined    map[[4]byte]bool
	joinedMAC map[[6]byte]bool
}

func newMulticastJoiner(fd, ifIndex int) *multicastJoiner {
	return &multicastJoiner{fd: fd, ifIndex: ifIndex, joined: make(map[[4]byte]bool), joinedMAC: make(map[[6]byte]bool)}
}

// multicastMAC maps an IPv4 multicast group to its Ethernet address:
// 01:00:5e + the low 23 bits of the group (RFC 1112).
func multicastMAC(group [4]byte) [6]byte {
	return [6]byte{0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]}
}

// join programs the NIC hardware multicast filter for group on the AF_PACKET
// socket (idempotent), so the kernel delivers that group to us WITHOUT
// promiscuous. This is the packet-socket-correct mechanism: IP_ADD_MEMBERSHIP is
// an AF_INET/L3 option and returns ENOPROTOOPT on a packet socket - we use
// PACKET_ADD_MEMBERSHIP / PACKET_MR_MULTICAST with the derived multicast MAC.
//
// CAVEAT (hardware-verify, R1): this opens the *local* NIC filter but emits no
// IGMP membership report, so on an IGMP-snooping switch the upstream may still
// prune the group from our port. Getting snooped multicast forwarded requires a
// real IGMP join (a parallel AF_INET socket doing IP_ADD_MEMBERSHIP) - deferred
// until validated on the Pi. Until then the promiscuous duty-cycle remains the
// reliable multicast path; this join is the cheap steady-state optimisation.
func (m *multicastJoiner) join(group [4]byte) error {
	if m.joined[group] {
		return nil
	}
	if err := m.membership(multicastMAC(group), unix.PACKET_ADD_MEMBERSHIP); err != nil {
		return err
	}
	m.joined[group] = true
	return nil
}

// joinMAC programs the NIC filter for a raw L2 multicast MAC that is not derived
// from an IPv4 group (LLDP/CDP/STP); same PACKET_MR_MULTICAST mechanism as join.
func (m *multicastJoiner) joinMAC(mac [6]byte) error {
	if m.joinedMAC[mac] {
		return nil
	}
	if err := m.membership(mac, unix.PACKET_ADD_MEMBERSHIP); err != nil {
		return err
	}
	m.joinedMAC[mac] = true
	return nil
}

// membership adds or drops one multicast-MAC membership on the packet socket.
func (m *multicastJoiner) membership(mac [6]byte, op int) error {
	mreq := &unix.PacketMreq{Ifindex: int32(m.ifIndex), Type: unix.PACKET_MR_MULTICAST, Alen: 6}
	copy(mreq.Address[:], mac[:])
	return unix.SetsockoptPacketMreq(m.fd, unix.SOL_PACKET, op, mreq)
}

// joinKnown joins all directly-joinable groups (PTP/mDNS IPv4 groups plus the
// LLDP/CDP/STP L2 control MACs), returning the first error if any (best-effort:
// it attempts every group regardless).
func (m *multicastJoiner) joinKnown() error {
	var firstErr error
	for _, g := range knownGroups {
		if err := m.join(g); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, mac := range knownMACs {
		if err := m.joinMAC(mac); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
