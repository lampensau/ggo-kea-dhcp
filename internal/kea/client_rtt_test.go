package kea

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// harness_kea_client_test.go: verification tests for the SendCommand RTT-accounting
// change - LastRTT is now recorded ONLY on an HTTP 200, not on a non-200 - and for
// the reachability bookkeeping on each path.

// TestLastRTTRecordedOn200 proves a successful call advances LastRTT off its
// zero value and marks the socket reachable.
func TestLastRTTRecordedOn200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Small delay so the measured RTT is reliably non-zero.
		time.Sleep(2 * time.Millisecond)
		_, _ = w.Write([]byte(`[{"result":0,"text":"ok"}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", "")
	if c.LastRTT() != 0 {
		t.Fatalf("LastRTT before any call = %v, want 0", c.LastRTT())
	}
	if _, err := c.SendCommand("config-get", nil); err != nil {
		t.Fatalf("SendCommand: %v", err)
	}
	if c.LastRTT() <= 0 {
		t.Errorf("LastRTT after a 200 = %v, want > 0", c.LastRTT())
	}
	if !c.Reachable() {
		t.Error("Reachable() should be true after a 200")
	}
}

// TestLastRTTNotRecordedOn500 is the core of the diff: a non-200 response must
// NOT update LastRTT (the tile reflects only successful lease-processing latency),
// even though the socket is still considered reachable (Kea answered).
func TestLastRTTNotRecordedOn500(t *testing.T) {
	status := http.StatusInternalServerError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == http.StatusOK {
			time.Sleep(2 * time.Millisecond)
			_, _ = w.Write([]byte(`[{"result":0,"text":"ok"}]`))
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("kea exploded"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", "")

	// First, a pure 500 against a fresh client: LastRTT must stay at its zero value.
	if _, err := c.SendCommand("config-get", nil); err == nil {
		t.Fatal("expected a non-200 error from SendCommand")
	}
	if c.LastRTT() != 0 {
		t.Errorf("LastRTT after only a 500 = %v, want 0 (RTT not recorded on non-200)", c.LastRTT())
	}
	// A non-200 still means the socket answered → reachable stays true.
	if !c.Reachable() {
		t.Error("Reachable() should be true after a non-200 (Kea answered)")
	}

	// Now record a real RTT with a 200, then fire a 500 and assert the prior RTT is
	// preserved (the 500 path does not touch lastRTT at all).
	status = http.StatusOK
	if _, err := c.SendCommand("config-get", nil); err != nil {
		t.Fatalf("SendCommand 200: %v", err)
	}
	good := c.LastRTT()
	if good <= 0 {
		t.Fatalf("LastRTT after 200 = %v, want > 0", good)
	}
	status = http.StatusInternalServerError
	if _, err := c.SendCommand("config-get", nil); err == nil {
		t.Fatal("expected a non-200 error on the second 500")
	}
	if c.LastRTT() != good {
		t.Errorf("LastRTT after a 500 following a 200 = %v, want unchanged %v", c.LastRTT(), good)
	}
}

// TestSendCommandTransportFailureUnreachable covers the transport-error arm:
// a dead endpoint flips reachable false and records a lastErr, and (per the change)
// must not advance LastRTT.
func TestSendCommandTransportFailureUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // make the endpoint unreachable

	c := NewClient(url, "", "")
	if _, err := c.SendCommand("config-get", nil); err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
	if c.Reachable() {
		t.Error("Reachable() should be false after a transport failure")
	}
	if c.LastError() == "" {
		t.Error("LastError() should be set after a transport failure")
	}
	if c.LastRTT() != 0 {
		t.Errorf("LastRTT after a transport failure = %v, want 0", c.LastRTT())
	}
}
