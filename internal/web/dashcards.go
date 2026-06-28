package web

import (
	"log"
	"time"

	"ggo-kea-dhcp/internal/kea"
	"ggo-kea-dhcp/internal/web/views"
)

// fetchRecentActivity reads the latest n audit rows for the dashboard activity
// feed (same query as the full Audit page, just capped tighter).
func (s *Server) fetchRecentActivity(n int) []views.AuditRow {
	rows, err := s.sqlite.Query("SELECT ts, actor, action, target, result FROM audit_log ORDER BY ts DESC LIMIT ?", n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []views.AuditRow
	for rows.Next() {
		var a views.AuditRow
		if rows.Scan(&a.Timestamp, &a.Actor, &a.Action, &a.Target, &a.Result) == nil {
			a.Timestamp = localAuditTime(a.Timestamp)
			out = append(out, a)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("[Dashboard] activity feed iteration: %v", err)
	}
	return out
}

// localAuditTime renders a stored-UTC audit timestamp in the appliance's local
// timezone, so audit/activity rows match the system clock (the Pi runs CEST,
// time.Local follows /etc/localtime). The pure-Go SQLite driver (CGO off) parses a
// DATETIME column into a time.Time, which database/sql then renders into this string
// field as RFC3339-UTC ("2006-01-02T15:04:05Z") - so that is the real input. The
// space-separated SQLite-native form is accepted as a fallback for other paths/tests.
// An unparseable value is shown as-is rather than dropped.
func localAuditTime(ts string) string {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Local().Format("2006-01-02 15:04:05")
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.UTC); err == nil {
		return t.Local().Format("2006-01-02 15:04:05")
	}
	return ts
}

// topLeases returns the first n lease rows (buildLeaseRows is IP-sorted) for the
// dashboard's active-leases summary; the full table lives on /leases.
func topLeases(rows []views.LeaseRow, n int) []views.LeaseRow {
	if len(rows) > n {
		return rows[:n]
	}
	return rows
}

// fetchPinningSplit merges the MariaDB host reservations with the active leases
// and SQLite labels, then splits into pinned (configured) and learnable ports.
// One fetch serves the dashboard pinnings card and the /pinning page live regions.
// Returns nil, nil when MariaDB is absent or a query fails (graceful empty state).
func (s *Server) fetchPinningSplit(leases []kea.ActiveLease) (pinned, learnable []views.PortRow) {
	if s.mariadb == nil {
		return nil, nil
	}
	labels, err1 := s.fetchPortLabels()
	pinnedMap, err2 := s.fetchPinnedPorts()
	if err1 != nil || err2 != nil {
		return nil, nil
	}
	// activeLeases (not the raw set) to match the /pinning page (pinning.go): an
	// expired-not-yet-reclaimed lease must not surface a phantom learnable port on the
	// dashboard/live card that /pinning doesn't show.
	for _, p := range mergePortRows(labels, pinnedMap, activeLeases(leases), s.lastSeenSnapshot(), time.Now().Unix()) {
		if p.Pinned {
			pinned = append(pinned, p)
		} else {
			learnable = append(learnable, p)
		}
	}
	return pinned, learnable
}
