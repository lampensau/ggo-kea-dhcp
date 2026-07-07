-- Drop the dead scopes.iface_mode column. It was NOT NULL boilerplate every insert
-- had to carry, but no read path ever selected it: the interface mode is derived from
-- vlan_id (vlan > 0 => trunk, else physical) at the one place that needs it. No index
-- or trigger references it, so the drop is clean.
ALTER TABLE scopes DROP COLUMN iface_mode;
