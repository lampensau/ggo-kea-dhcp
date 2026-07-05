package dns

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// resolvTTL bounds how often /etc/resolv.conf is re-read. NetworkManager
// rewrites it when the WiFi uplink comes or goes; a few seconds of staleness
// only delays the SERVFAIL/forward flip, never breaks it.
const resolvTTL = 5 * time.Second

// resolvCache reads the upstream resolvers from a resolv.conf-format file with
// a short-lived cache. The appliance has no resolvectl/NM DNS plumbing - the
// file IS the interface NetworkManager maintains for the uplink's DNS servers.
type resolvCache struct {
	path string

	mu      sync.Mutex
	fetched time.Time
	servers []string
}

func newResolvCache(path string) *resolvCache {
	if path == "" {
		path = "/etc/resolv.conf"
	}
	return &resolvCache{path: path}
}

// upstreams returns the usable upstream resolver addresses, excluding any of
// our own bind addresses (a resolv.conf pointing back at the appliance must
// not become a forward loop). Empty means isolated: the caller answers
// SERVFAIL for anything outside the local zones.
func (r *resolvCache) upstreams(exclude map[string]bool) []string {
	r.mu.Lock()
	if time.Since(r.fetched) > resolvTTL {
		r.servers = parseResolvConf(r.path)
		r.fetched = time.Now()
	}
	servers := r.servers
	r.mu.Unlock()

	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if !exclude[s] {
			out = append(out, s)
		}
	}
	return out
}

// parseResolvConf extracts the nameserver lines from a resolv.conf file. A
// missing or unreadable file is simply "no upstream".
func parseResolvConf(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			out = append(out, fields[1])
		}
	}
	return out
}
