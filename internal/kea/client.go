package kea

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Client represents a client for Kea's HTTP API socket.
type Client struct {
	apiURL     string
	username   string
	password   string
	httpClient *http.Client
	// lastRTT is the round-trip duration (ns) of the most recent successful
	// control-socket call. Every command funnels through SendCommand, so this
	// tracks real lease-serving latency for the dashboard's "lease processing"
	// tile. Atomic: read off the metrics sampler goroutine, written on the call path.
	lastRTT atomic.Int64
	// reachable records whether the most recent SendCommand transport call reached
	// Kea (the HTTP Do succeeded), regardless of whether the command itself
	// errored - a non-200 or a command result != 0 still means Kea answered. The
	// runtime backend-health monitor reads this to warn when Kea is down.
	reachable atomic.Bool
	// lastErr is the transport error string from the most recent unreachable call
	// (""=reachable). atomic.Value holds a string.
	lastErr atomic.Value
}

// NewClient creates a new Kea API client.
func NewClient(apiURL, username, password string) *Client {
	return &Client{
		apiURL:   apiURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// LastRTT returns the round-trip duration of the most recent successful control-
// socket call (zero before the first call). Drives the dashboard's "lease
// processing" stat tile.
func (c *Client) LastRTT() time.Duration {
	return time.Duration(c.lastRTT.Load())
}

// Request represents the JSON payload structure for Kea commands.
type Request struct {
	Command   string   `json:"command"`
	Service   []string `json:"service"`
	Arguments any      `json:"arguments,omitempty"`
}

// Response represents the JSON response structure from Kea.
type Response struct {
	Result    int             `json:"result"`
	Text      string          `json:"text"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// SendCommand sends a command to the Kea HTTP API and returns the first response.
func (c *Client) SendCommand(command string, args any) (*Response, error) {
	reqPayload := Request{
		Command:   command,
		Service:   []string{"dhcp4"},
		Arguments: args,
	}

	body, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal kea request: %w", err)
	}

	req, err := http.NewRequest("POST", c.apiURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.reachable.Store(false)
		c.lastErr.Store(err.Error())
		return nil, fmt.Errorf("http request to kea failed: %w", err)
	}
	// Kea answered (even a non-200/result!=0 means the socket is up).
	c.reachable.Store(true)
	c.lastErr.Store("")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kea api returned non-200 status: %d, response: %s", resp.StatusCode, string(respBody))
	}
	// Record RTT only for a successful call (LastRTT feeds the "lease processing" tile).
	c.lastRTT.Store(int64(time.Since(start)))

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read kea response body: %w", err)
	}

	// Kea API returns an array of responses, one for each targeted service.
	var responses []Response
	if err := json.Unmarshal(respBytes, &responses); err != nil {
		// Sometimes Kea might return a single object or error object if something goes wrong
		var singleResponse Response
		if errSingle := json.Unmarshal(respBytes, &singleResponse); errSingle == nil {
			responses = []Response{singleResponse}
		} else {
			return nil, fmt.Errorf("failed to unmarshal kea response array (raw response: %s): %w", string(respBytes), err)
		}
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("empty response array from kea")
	}

	res := responses[0]
	if res.Result != 0 {
		return &res, fmt.Errorf("kea command %s failed (result %d): %s", command, res.Result, res.Text)
	}

	return &res, nil
}

// Reachable reports whether the most recent control-socket call reached Kea. It
// is false before the first call and after any transport failure. Drives the
// runtime "DHCP Server Offline" warning.
func (c *Client) Reachable() bool { return c.reachable.Load() }

// LastError returns the transport error from the most recent unreachable call,
// or "" when Kea was last reachable.
func (c *Client) LastError() string {
	if v, ok := c.lastErr.Load().(string); ok {
		return v
	}
	return ""
}

// Ping reports whether Kea's control socket is reachable and answering. It issues
// version-get (a cheap, always-available command); a nil return means Kea
// responded, any error means the socket is down, unauthorized, or misconfigured.
func (c *Client) Ping() error {
	_, err := c.SendCommand("version-get", nil)
	return err
}

// ReloadConfig triggers Kea to reload its configuration from the disk.
func (c *Client) ReloadConfig() error {
	_, err := c.SendCommand("config-reload", nil)
	return err
}

// DeleteLease removes a single IPv4 lease via lease4-del. A "lease not found"
// (Kea result 3) is treated as success - the caller wanted the address to have no
// lease and it already has none. Used to free an address so a host reservation or a
// pool-class change takes effect on the device's next renewal.
func (c *Client) DeleteLease(ip string) error {
	res, err := c.SendCommand("lease4-del", map[string]any{"ip-address": ip})
	if err != nil {
		if res != nil && res.Result == 3 {
			return nil // no such lease - nothing to delete
		}
		return err
	}
	return nil
}

// WipeLeases removes ALL leases from every subnet via lease4-wipe (subnet-id 0). Used on
// a reset so the prior job's leases - and the learnable Option-82 ports derived from them
// - don't survive into the next job (leases are memfile and persist across a config
// reload). Requires memfile storage + the lease_cmds hook, both present here. A "no
// leases" result (Kea result 3) is treated as success.
func (c *Client) WipeLeases() error {
	res, err := c.SendCommand("lease4-wipe", map[string]any{"subnet-id": 0})
	if err != nil {
		if res != nil && res.Result == 3 {
			return nil // nothing to wipe
		}
		return err
	}
	return nil
}

// ActiveLease represents a DHCP lease returned by Kea.
type ActiveLease struct {
	IPAddress string `json:"ip-address"`
	HWAddress string `json:"hw-address"`
	ClientID  string `json:"client-id"`
	ValidLft  int64  `json:"valid-lft"`
	// Cltt is the client last transaction time (epoch seconds). Kea does NOT emit an
	// absolute "expire" field; the lease expiry is cltt + valid-lft, computed here.
	Cltt     int64  `json:"cltt"`
	SubnetID int    `json:"subnet-id"`
	Hostname string `json:"hostname,omitempty"`
	State    int    `json:"state"`
}

// GetLeases retrieves all leases from Kea, paging through lease4-get-page with
// the `from` cursor so result sets larger than one page are fully returned.
// pageSize controls the per-request page size.
func (c *Client) GetLeases(pageSize int) ([]ActiveLease, error) {
	if pageSize <= 0 {
		pageSize = 1000
	}

	var all []ActiveLease
	from := "start"

	for {
		args := map[string]any{
			"limit": pageSize,
			"from":  from,
		}
		res, err := c.SendCommand("lease4-get-page", args)
		if err != nil {
			// Kea returns result 3 when there are no (more) leases - a normal
			// terminal state, not a command failure.
			if res != nil && res.Result == 3 {
				break
			}
			return all, err
		}

		var out struct {
			Leases []ActiveLease `json:"leases"`
		}
		if err := json.Unmarshal(res.Arguments, &out); err != nil {
			return all, fmt.Errorf("failed to parse leases response: %w", err)
		}

		all = append(all, out.Leases...)
		if len(out.Leases) < pageSize {
			break // last (partial) page
		}
		// Next page starts after the last address returned.
		from = out.Leases[len(out.Leases)-1].IPAddress
	}

	return all, nil
}
