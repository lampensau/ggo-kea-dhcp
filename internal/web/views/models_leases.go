package views

// --- Leases ---

type LeasesView struct {
	Page       PageData
	Leases     []LeaseRow // unified: active leases + client reservations (Reserved flag)
	CanReserve bool       // MariaDB host store online
	Error      string
}

// LeaseRow is one active DHCP lease as displayed.
type LeaseRow struct {
	IPAddress string
	HWAddress string
	ClientID  string
	Hostname  string
	Class     string
	ExpiresIn string
	// ExpiresAt is the absolute lease-expiry epoch (seconds): >0 a real expiry the
	// client counts down live (data-expires), 0 unknown, -1 infinite ("never").
	// Absolute so a cached/rebroadcast fragment never shows a stale countdown.
	ExpiresAt int64
	// Presence is the online/offline signal from the active ARP prober, keyed by this
	// row's IP: "online" (the device at this address answered an ARP recently), "offline"
	// (no answer), or "" (unknown - probing unavailable, so no indicator is shown).
	Presence string
	// Reserved is true when this device's MAC has a client (hardware-address) host
	// reservation - i.e. its IP is fixed, not dynamic. SubnetID is the reservation's
	// Kea subnet (needed to remove it).
	Reserved bool
	SubnetID int
	// PortPinned is true when this lease arrives on a switch port that has a flex-id
	// (Option-82) pin: the IP is fixed by the port, not the MAC. Such a device's IP is
	// governed by the port reservation (flex-id wins over hw-address in Kea's
	// host-reservation-identifiers order), so the leases page must NOT offer a MAC
	// reservation for it - that reservation would be silently shadowed. The row renders
	// like a reservation but its delete control is disabled (manage it on Port Pinning).
	PortPinned bool
	// LastSeen is the epoch (0 = never observed) the MAC was last active; LastSeenText
	// is its coarse "3d ago" rendering; Stale flags a reservation unseen for a long time.
	LastSeen     int64
	LastSeenText string
	Stale        bool
}
