package network

import (
	"fmt"
	"log"
	"strconv"
)

// ensureNATTable creates the ggo_nat table and the named chain if absent. Shared
// by the masquerade/port-forward helpers so the table/chain bootstrap lives in
// one place. hookSpec is the nft chain hook spec, e.g.
// "{ type nat hook postrouting priority 100; policy accept; }".
func (m *Manager) ensureNATChain(chain, hookSpec string) {
	_, _ = m.cmd.Run("nft", "add", "table", "ip", "ggo_nat")
	_, _ = m.cmd.Run("nft", "add", "chain", "ip", "ggo_nat", chain, hookSpec)
}

// SetIPForwarding enables or disables IPv4 packet forwarding in the kernel.
func (m *Manager) SetIPForwarding(enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	log.Printf("Setting sysctl net.ipv4.ip_forward to %s...", val)
	_, err := m.cmd.Run("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", val))
	return err
}

// ApplyMasquerade sets up (or tears down) nftables NAT masquerading for traffic
// leaving the uplink interface.
func (m *Manager) ApplyMasquerade(uplinkIface string, enabled bool) error {
	log.Printf("Applying nftables masquerade on %s (enabled: %t)...", uplinkIface, enabled)
	m.ensureNATChain("postrouting", "{ type nat hook postrouting priority 100; policy accept; }")

	// Flush first so repeated applies (e.g. boot converge re-runs) don't stack
	// duplicate rules.
	if _, err := m.cmd.Run("nft", "flush", "chain", "ip", "ggo_nat", "postrouting"); err != nil {
		return err
	}
	if enabled {
		_, err := m.cmd.Run("nft", "add", "rule", "ip", "ggo_nat", "postrouting", "oifname", uplinkIface, "masquerade")
		return err
	}
	return nil
}

// AddPortForward adds a DNAT rule forwarding externalPort on the uplink to
// localIP:localPort.
func (m *Manager) AddPortForward(uplinkIface, localIP string, localPort, externalPort int, proto string) error {
	log.Printf("Adding port forward: %s:%d -> %s:%d (%s) on %s...", uplinkIface, externalPort, localIP, localPort, proto, uplinkIface)
	m.ensureNATChain("prerouting", "{ type nat hook prerouting priority -100; policy accept; }")

	// Pass each nft token as a separate argument so a space in an interface name
	// can't smuggle extra rule syntax.
	_, err := m.cmd.Run("nft", "add", "rule", "ip", "ggo_nat", "prerouting",
		"iifname", uplinkIface, proto, "dport", strconv.Itoa(externalPort),
		"dnat", "to", fmt.Sprintf("%s:%d", localIP, localPort))
	return err
}

// ClearPortForwards flushes the prerouting chain in the ggo_nat table.
func (m *Manager) ClearPortForwards() error {
	log.Println("Clearing all ggo-kea-dhcp port forwarding rules...")
	m.ensureNATChain("prerouting", "{ type nat hook prerouting priority -100; policy accept; }")
	_, err := m.cmd.Run("nft", "flush", "chain", "ip", "ggo_nat", "prerouting")
	return err
}
