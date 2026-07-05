package views

import (
	"strings"
	"testing"
)

// TestLeasesBodyPinnedReservedActions covers the reservation/pin action states in the
// leases table. A pinned-port row is never deletable here (the pin is managed on the
// Port Pinning page) and is marked distinctly from a hw-address reservation - even when
// the same device also has a leftover reservation; that reservation stays deletable on
// its own (non-pinned) row, never from the pinned row.
func TestLeasesBodyPinnedReservedActions(t *testing.T) {
	row := func(r LeaseRow) string {
		return render(t, LeasesBody([]LeaseRow{r}, true))
	}

	// Pure pinned: a disabled remove control, NOT a remove-reservation action,
	// marked with the switch-port (not reservation) indicator next to the IP.
	pinnedOnly := row(LeaseRow{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:20:aa:bb", Class: "GGO-BPX", PortPinned: true})
	if strings.Contains(pinnedOnly, "ggoResvDelOpen") {
		t.Error("pinned row must not offer a remove-reservation action")
	}
	if !strings.Contains(pinnedOnly, "disabled") {
		t.Error("pinned row should render a disabled remove control")
	}
	if !strings.Contains(pinnedOnly, "lease-pinned") || !strings.Contains(pinnedOnly, "Pinned by switch port") {
		t.Error("pinned row should use the distinct switch-port marker, not the reservation pin")
	}

	// Pinned AND a leftover hw reservation: still NOT deletable from the pinned row (the
	// reservation is cleared from its own separate row), and still marked as a port pin.
	both := row(LeaseRow{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:20:aa:bb", Class: "GGO-BPX", PortPinned: true, Reserved: true, SubnetID: 1})
	if strings.Contains(both, "ggoResvDelOpen") {
		t.Error("a pinned row must never offer a delete, even with a leftover reservation")
	}
	if !strings.Contains(both, "disabled") {
		t.Error("pinned+reserved row should still render the disabled remove control")
	}

	// Pure reservation (not pinned): the ordinary remove action (a button opening
	// the shared dialog), marked with the reservation pin (not the switch-port
	// marker) and carrying the target in data attributes.
	reserved := row(LeaseRow{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:20:aa:bb", Class: "GGO-BPX", Reserved: true, SubnetID: 1})
	if !strings.Contains(reserved, "ggoResvDelOpen") || !strings.Contains(reserved, `data-subnet="1"`) {
		t.Error("reserved-only row should render the remove-reservation dialog opener")
	}
	if !strings.Contains(reserved, "lease-reserved") || strings.Contains(reserved, "lease-pinned") {
		t.Error("reserved-only row should use the reservation pin marker, not the switch-port marker")
	}

	// A reserved/pinned row with an ACTIVE lease shows its real remaining time, not "—"
	// (the device renews and keeps the same fixed IP, but the lease still counts down).
	leasedPin := row(LeaseRow{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:20:aa:bb", Class: "GGO-BPX", PortPinned: true, ExpiresIn: "1h58m"})
	if !strings.Contains(leasedPin, "1h58m") {
		t.Error("a pinned row with an active lease should show its remaining lease time")
	}
	// An offline reservation (no active lease, empty ExpiresIn) shows the em dash.
	offlineRsv := row(LeaseRow{IPAddress: "10.0.0.9", HWAddress: "00:1f:80:20:aa:bb", Class: "GGO-BPX", Reserved: true, SubnetID: 1})
	if !strings.Contains(offlineRsv, "—") {
		t.Error("an offline reservation (no lease) should show an em-dash expiry")
	}
}
