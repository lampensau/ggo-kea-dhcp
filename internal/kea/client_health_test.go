package kea

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestKeaHealthSnapshotConsistent pins the paired reachable+error semantics that the
// single-pointer snapshot guarantees: reachable and the error are published together,
// so Health never yields a reachable=true with a stale error (or reachable=false with
// none), and Reachable()/LastError() derive from that same snapshot.
func TestKeaHealthSnapshotConsistent(t *testing.T) {
	// Before any call: the zero snapshot.
	fresh := NewClient("http://127.0.0.1:0", "", "")
	if r, e := fresh.Health(); r || e != "" {
		t.Fatalf("Health before any call = (%v, %q), want (false, \"\")", r, e)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"result":0,"text":"ok"}]`))
	}))
	c := NewClient(srv.URL, "", "")

	if _, err := c.SendCommand(t.Context(), "config-get", nil); err != nil {
		t.Fatalf("SendCommand: %v", err)
	}
	if r, e := c.Health(); !r || e != "" {
		t.Fatalf("Health after a reachable call = (%v, %q), want (true, \"\")", r, e)
	} else if r != c.Reachable() || e != c.LastError() {
		t.Fatal("Health() disagrees with Reachable()/LastError() after a reachable call")
	}

	// Transport failure: the snapshot flips to (false, non-empty) as one write - never a
	// torn (true, err) or (false, "").
	srv.Close()
	if _, err := c.SendCommand(t.Context(), "config-get", nil); err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
	if r, e := c.Health(); r || e == "" {
		t.Fatalf("Health after a transport failure = (%v, %q), want (false, non-empty)", r, e)
	} else if r != c.Reachable() || e != c.LastError() {
		t.Fatal("Health() disagrees with Reachable()/LastError() after a transport failure")
	}
}
