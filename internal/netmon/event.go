package netmon

// Event is an edge-triggered, auditable transition emitted by a detector's Tick
// on a confirmed state change. It maps to a SQLite audit row through the injected
// EventSink - the web layer supplies a closure over SQLiteDB.LogAudit, deriving
// the audit Result string from Severity (so a rogue-DHCP error and a benign
// notice read distinctly) - so netmon imports neither web nor db.
type Event struct {
	Action   string
	Target   string
	Before   string
	After    string
	Severity Severity
}

// EventSink consumes confirmed transitions. A nil sink is valid (events are
// dropped) so a Monitor can run without audit wiring in tests.
type EventSink func(Event)
