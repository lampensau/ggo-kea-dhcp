package db

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type MariaDB struct {
	*sql.DB
}

// ConnectMariaDB establishes a connection to the Kea MariaDB database. An empty DSN
// is treated as "not configured" (a documented degraded mode - dynamic leases still
// serve, only reservations/pinning are unavailable) rather than silently connecting
// with a default credential.
func ConnectMariaDB(dsn string) (*MariaDB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("no MariaDB DSN configured")
	}
	// Bound the TCP connect/read so a routable-but-silent DSN host can't stall
	// boot for the OS default (~127s) on the synchronous Ping() in VerifySchema /
	// preflight. Default only when the operator hasn't set their own.
	if cfg, perr := mysql.ParseDSN(dsn); perr == nil {
		if cfg.Timeout == 0 {
			cfg.Timeout = 5 * time.Second
		}
		if cfg.ReadTimeout == 0 {
			cfg.ReadTimeout = 10 * time.Second
		}
		dsn = cfg.FormatDSN()
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open mysql connection: %w", err)
	}

	// Set connection limits appropriate for a Pi 4 (2GB) running a tight memory footprint
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	// Recycle connections so a pooled handle that went stale across a MariaDB
	// restart is discarded and transparently reopened on next use - this is what
	// lets the appliance recover from a MariaDB outage without restarting.
	db.SetConnMaxLifetime(3 * time.Minute)

	return &MariaDB{db}, nil
}

// VerifySchema checks if Kea's tables (hosts, lease4) exist and are queryable.
// It returns an error if the schema is not initialized.
func (m *MariaDB) VerifySchema() error {
	// Ping first to verify network/access health
	if err := m.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Check if the 'hosts' table exists and is accessible
	_, err := m.Exec("SELECT 1 FROM hosts LIMIT 1")
	if err != nil {
		return fmt.Errorf("kea schema hosts table verification failed (check if kea-admin db-init mysql was run): %w", err)
	}

	log.Println("MariaDB schema verification succeeded. Hosts table is active.")
	return nil
}

// HostReservation represents a row in Kea's MySQL hosts table.
type HostReservation struct {
	ID                int
	Identifier        []byte // Binary hex representation of hardware address or flex-id
	IdentifierType    int    // Type: 0 = HW Address, 4 = Flex-ID
	SubnetID          int
	IPv4Address       uint32 // INET_ATON representation
	Hostname          string
	Option82CircuitID string // optional metadata for UI tracking
	Option82RemoteID  string // optional metadata for UI tracking
}

// InsertReservation inserts a single host reservation directly into MariaDB.
func (m *MariaDB) InsertReservation(res HostReservation) error {
	_, err := m.Exec(`
		INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			ipv4_address = VALUES(ipv4_address),
			hostname = VALUES(hostname)`,
		res.Identifier, res.IdentifierType, res.SubnetID, res.IPv4Address, res.Hostname)
	return err
}

// InsertReservations inserts many host reservations in one transaction, reusing a
// prepared statement per row - so restoring a box with hundreds of pins is one
// batched commit rather than hundreds of serial round-trips to MariaDB.
func (m *MariaDB) InsertReservations(res []HostReservation) error {
	if len(res) == 0 {
		return nil
	}
	tx, err := m.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			ipv4_address = VALUES(ipv4_address),
			hostname = VALUES(hostname)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range res {
		if _, err := stmt.Exec(r.Identifier, r.IdentifierType, r.SubnetID, r.IPv4Address, r.Hostname); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// HWReservations returns all client (hardware-address, type 0) reservations - the
// per-device fixed-IP entries managed from the leases view, distinct from the
// flex-id (type 4) switch-port pins.
func (m *MariaDB) HWReservations() ([]HostReservation, error) {
	rows, err := m.Query("SELECT dhcp_identifier, dhcp4_subnet_id, ipv4_address, hostname FROM hosts WHERE dhcp_identifier_type = 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostReservation
	for rows.Next() {
		var res HostReservation
		var ipVal uint32
		if err := rows.Scan(&res.Identifier, &res.SubnetID, &ipVal, &res.Hostname); err != nil {
			return nil, err
		}
		res.IdentifierType = 0
		res.IPv4Address = ipVal
		out = append(out, res)
	}
	return out, rows.Err()
}

// AllReservations returns every row in Kea's hosts table - both type-0 MAC
// reservations and type-4 flex-id port pins - for a full appliance backup.
func (m *MariaDB) AllReservations() ([]HostReservation, error) {
	rows, err := m.Query("SELECT dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname FROM hosts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostReservation
	for rows.Next() {
		var res HostReservation
		var ipVal uint32
		if err := rows.Scan(&res.Identifier, &res.IdentifierType, &res.SubnetID, &ipVal, &res.Hostname); err != nil {
			return nil, err
		}
		res.IPv4Address = ipVal
		out = append(out, res)
	}
	return out, rows.Err()
}

// ReservationByIP returns the host reservation (if any) currently mapping ip in the
// given subnet, and whether one was found. Used to refuse assigning an address that is
// already reserved or pinned to a DIFFERENT device: Kea's hosts unique key is
// (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id) and excludes ipv4_address, so
// a blind INSERT ... ON DUPLICATE KEY would create a SECOND row for one IP rather than
// dedupe it.
func (m *MariaDB) ReservationByIP(subnetID int, ip uint32) (HostReservation, bool, error) {
	var res HostReservation
	var ipVal uint32
	err := m.QueryRow(`
		SELECT dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname
		FROM hosts WHERE dhcp4_subnet_id = ? AND ipv4_address = ? LIMIT 1`,
		subnetID, ip).Scan(&res.Identifier, &res.IdentifierType, &res.SubnetID, &ipVal, &res.Hostname)
	if err == sql.ErrNoRows {
		return HostReservation{}, false, nil
	}
	if err != nil {
		return HostReservation{}, false, err
	}
	res.IPv4Address = ipVal
	return res, true, nil
}

// DeleteReservation deletes a host reservation by identifier + type, returning the
// number of rows removed. It deliberately does NOT scope by subnet: a device maps to a
// single reservation, and keying the delete on a form-supplied subnet_id let a stale or
// mismatched value silently delete zero rows while reporting success - leaving a live,
// unclearable pin. Rows-affected lets the caller tell the operator nothing matched.
func (m *MariaDB) DeleteReservation(identifier []byte, identifierType int) (int64, error) {
	res, err := m.Exec(`
		DELETE FROM hosts
		WHERE dhcp_identifier = ? AND dhcp_identifier_type = ?`,
		identifier, identifierType)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteAllReservations clears every host reservation (port pins AND MAC
// reservations) from Kea's host store. Used by the reset paths: the data plane is
// per-job state, so returning to onboarding / factory must not leave a previous
// event's pins and reserved leases live (they survive a config reload because they
// live in the DB, not the config file).
func (m *MariaDB) DeleteAllReservations() error {
	_, err := m.Exec("DELETE FROM hosts")
	return err
}
