-- Initial schema for ggo-kea-dhcp (control plane / SQLite).
-- Consolidated from the prototype incremental migrations at the 1.1.0 cut.
-- Fresh installs start at user_version 1 - there is no upgrade path from
-- pre-1.1.0 databases (prototype installs are not migrated).

CREATE TABLE app_state (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
CREATE TABLE profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    active INTEGER DEFAULT 0, -- 1 if active, 0 otherwise
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    iface_mode TEXT NOT NULL, -- e.g. "trunk", "access", "physical"
    vlan_id INTEGER,          -- null if untagged
    cidr TEXT NOT NULL,       -- e.g. "10.0.0.0/23"
    pool_spec TEXT,           -- marshalled DeviceCounts (per-class forecast)
    uplink_json TEXT,         -- marshalled UplinkConfig (enabled/ssid/password)
    preset TEXT, pool_plan TEXT, multicast_sniff INTEGER DEFAULT 0, services_json TEXT, name TEXT,              -- e.g. "greengo", "dante", "generic"
    FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE TABLE port_labels (
    flex_id_hex TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    location TEXT,
    notes TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    before_json TEXT,
    after_json TEXT,
    result TEXT NOT NULL
);
CREATE TABLE config_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL,
    path TEXT NOT NULL
);
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at DATETIME NOT NULL
, csrf_token TEXT, created_at DATETIME);
CREATE TABLE last_seen (
    identity TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX idx_audit_log_ts ON audit_log(ts);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
INSERT OR IGNORE INTO app_state (key, value) VALUES ('lifecycle_state', 'FACTORY');
