package kea

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// keaServer runs handler as a Kea control endpoint, capturing the last command name.
func keaServer(t *testing.T, handler func(req Request) string) (*Client, *string) {
	t.Helper()
	var lastCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(body, &req)
		lastCmd = req.Command
		_, _ = io.WriteString(w, handler(req))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "", ""), &lastCmd
}

func TestPingAndReloadCommands(t *testing.T) {
	c, lastCmd := keaServer(t, func(Request) string { return `[{"result":0}]` })
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if *lastCmd != "version-get" {
		t.Errorf("Ping sent %q want version-get", *lastCmd)
	}
	if err := c.ReloadConfig(); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	if *lastCmd != "config-reload" {
		t.Errorf("ReloadConfig sent %q want config-reload", *lastCmd)
	}
}

func TestDeleteLeaseResultContract(t *testing.T) {
	// result 3 ("no such lease") is success; any other non-zero result is an error.
	c3, _ := keaServer(t, func(Request) string { return `[{"result":3,"text":"not found"}]` })
	if err := c3.DeleteLease("10.0.0.9"); err != nil {
		t.Errorf("DeleteLease on missing lease should be nil, got %v", err)
	}

	c1, lastCmd := keaServer(t, func(Request) string { return `[{"result":1,"text":"boom"}]` })
	if err := c1.DeleteLease("10.0.0.9"); err == nil {
		t.Error("DeleteLease should propagate a genuine error (result 1)")
	}
	if *lastCmd != "lease4-del" {
		t.Errorf("DeleteLease sent %q want lease4-del", *lastCmd)
	}
}

func TestGetLeasesPagination(t *testing.T) {
	// Serve 2 full pages of 2 then a short page of 1: the loop must walk the `from`
	// cursor to the last IP and stop on the short page - 5 distinct leases, no dup.
	pages := map[string][]string{
		"start":    {"10.0.0.1", "10.0.0.2"},
		"10.0.0.2": {"10.0.0.3", "10.0.0.4"},
		"10.0.0.4": {"10.0.0.5"},
	}
	var fromSeen []string
	c, _ := keaServer(t, func(req Request) string {
		from := "start"
		if m, ok := req.Arguments.(map[string]any); ok {
			if f, ok := m["from"].(string); ok {
				from = f
			}
		}
		fromSeen = append(fromSeen, from)
		ips := pages[from]
		var b strings.Builder
		for i, ip := range ips {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"ip-address":%q}`, ip)
		}
		return fmt.Sprintf(`[{"result":0,"arguments":{"leases":[%s]}}]`, b.String())
	})

	leases, err := c.GetLeases(2)
	if err != nil {
		t.Fatalf("GetLeases: %v", err)
	}
	if len(leases) != 5 {
		t.Fatalf("got %d leases want 5: %+v", len(leases), leases)
	}
	seen := map[string]bool{}
	for _, l := range leases {
		if seen[l.IPAddress] {
			t.Errorf("duplicate lease %s (cursor advanced wrong)", l.IPAddress)
		}
		seen[l.IPAddress] = true
	}
	// Cursor must have advanced start -> 10.0.0.2 -> 10.0.0.4 and then stopped.
	want := []string{"start", "10.0.0.2", "10.0.0.4"}
	if strings.Join(fromSeen, ",") != strings.Join(want, ",") {
		t.Errorf("from cursors = %v want %v", fromSeen, want)
	}
}

func TestGetLeasesStopsOnResult3(t *testing.T) {
	// A full first page then result 3 (no more leases) must terminate cleanly.
	first := true
	c, _ := keaServer(t, func(Request) string {
		if first {
			first = false
			return `[{"result":0,"arguments":{"leases":[{"ip-address":"10.0.0.1"},{"ip-address":"10.0.0.2"}]}}]`
		}
		return `[{"result":3,"text":"no more leases"}]`
	})
	leases, err := c.GetLeases(2)
	if err != nil {
		t.Fatalf("GetLeases: %v", err)
	}
	if len(leases) != 2 {
		t.Errorf("got %d leases want 2", len(leases))
	}
}
