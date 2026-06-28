package web

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	uplinkProbeIface   = "wlan0"
	uplinkProbeTimeout = 1 * time.Second
)

// uplinkProbe measures round-trip reachability of the WiFi uplink's default
// gateway. It returns the dial RTT in ms when the gateway answers - a TCP connect
// OR a fast connection-refused both prove the gateway is reachable - or -1 when
// the uplink is offline/isolated (no default route, or the dial times out / has no
// route). The dashboard tile renders -1 as neutral "Offline", never red, since an
// isolated show network is the expected state. Runs on the always-on sampler, so
// the 1s timeout is bounded and off the request path. Pure Go, cgo-free.
func (s *Server) uplinkProbe() int {
	gw := defaultGateway(uplinkProbeIface)
	if gw == "" {
		return -1
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(gw, "80"), uplinkProbeTimeout)
	elapsed := int(time.Since(start) / time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return elapsed
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return elapsed // reachable: the host answered with an RST
	}
	return -1 // timeout / no route -> offline
}

// defaultGateway reads the IPv4 default-route gateway for iface from
// /proc/net/route (no exec). Returns "" when there is no default route on iface.
func defaultGateway(iface string) string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // column header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags ...; the default route has Destination 0.
		if len(fields) < 3 || fields[0] != iface || fields[1] != "00000000" {
			continue
		}
		if ip := hexLEtoIP(fields[2]); ip != "" {
			return ip
		}
	}
	_ = sc.Err() // a /proc/net/route read error is treated as "no default route"
	return ""
}

// hexLEtoIP converts a /proc/net/route little-endian hex address (e.g. "0100A8C0")
// to a dotted IPv4 string ("192.168.0.1"). Returns "" on a malformed or 0 address.
func hexLEtoIP(h string) string {
	if len(h) != 8 {
		return ""
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[3-i] = byte(v) // little-endian: low byte first
	}
	if b[0] == 0 {
		return ""
	}
	return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
}
