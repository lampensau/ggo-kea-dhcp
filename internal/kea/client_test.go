package kea

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWipeLeasesCommand asserts WipeLeases emits a well-formed lease4-wipe targeting all
// subnets (subnet-id 0) and treats a "no leases" result (Kea result 3) as success.
func TestWipeLeasesCommand(t *testing.T) {
	var gotCmd string
	var gotArgs map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(body, &req)
		gotCmd = req.Command
		if m, ok := req.Arguments.(map[string]any); ok {
			gotArgs = m
		}
		_, _ = w.Write([]byte(`[{"result":3,"text":"no leases for subnet 0"}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", "")
	if err := c.WipeLeases(); err != nil {
		t.Fatalf("WipeLeases on an empty store should succeed (result 3), got %v", err)
	}
	if gotCmd != "lease4-wipe" {
		t.Errorf("command = %q, want lease4-wipe", gotCmd)
	}
	// JSON numbers decode to float64 through the any-typed Arguments.
	if gotArgs["subnet-id"] != float64(0) {
		t.Errorf("subnet-id arg = %v, want 0 (all subnets)", gotArgs["subnet-id"])
	}
}
