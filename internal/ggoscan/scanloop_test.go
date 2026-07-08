package ggoscan

import (
	"net"
	"testing"
	"time"
)

// scanReplyNameMAC builds a minimal name+MAC device-scan reply, the same shape the
// parse tests construct, so recvLoop has a well-formed frame to record.
func scanReplyNameMAC(name string, mac [6]byte) []byte {
	body := make([]byte, 0x18)
	copy(body, name)
	copy(body[0x12:], mac[:])
	return append([]byte{0x47, 0x2d, 0x47, 0x00, 0x00, 0x11, 0x00, 0x00}, body...)
}

// TestScannerReceivesAndRecords drives the real Start/recvLoop/Snapshot/Stop goroutine
// layer over a loopback UDP socket, injected through the open seam: a reply written to
// the scanner's socket is parsed and recorded into the inventory, SendReboot on the live
// socket succeeds, and Stop tears the goroutines down. Before this the socket/goroutine
// layer had no runtime coverage - only the pure parse/inventory helpers did.
func TestScannerReceivesAndRecords(t *testing.T) {
	s := NewScanner()
	var conn *net.UDPConn
	s.open = func() (*net.UDPConn, error) {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err == nil {
			conn = c
		}
		return c, err
	}

	s.Start([]Spec{{Broadcast: [4]byte{127, 0, 0, 1}, LeaseIPs: func() []string { return nil }}})
	defer s.Stop()

	if conn == nil {
		t.Fatal("Start did not open a socket through the seam")
	}
	if !s.Snapshot().Available {
		t.Error("scanner should report Available after Start")
	}

	peer, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial scanner socket: %v", err)
	}
	defer peer.Close()
	if _, err := peer.Write(scanReplyNameMAC("Beltpack-07", [6]byte{0x00, 0x1f, 0x80, 0x01, 0x02, 0x03})); err != nil {
		t.Fatalf("write reply: %v", err)
	}

	// recvLoop records asynchronously; poll (bounded) rather than sleep a fixed time.
	var devs []Device
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if devs = s.Snapshot().Devices; len(devs) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(devs) != 1 || devs[0].MAC != "00:1f:80:01:02:03" {
		t.Fatalf("recvLoop did not record the reply; devices=%+v", devs)
	}

	// SendReboot on the live socket exercises the conn != nil branch.
	if err := s.SendReboot("127.0.0.1"); err != nil {
		t.Errorf("SendReboot on the live socket: %v", err)
	}

	s.Stop()
	if s.Snapshot().Available {
		t.Error("scanner should report unavailable after Stop")
	}
}

// TestSendRebootIdleAndInvalid covers SendReboot's other two branches: an invalid device
// address is rejected, and on an idle scanner (no live socket) it opens a one-shot socket
// through the seam and sends without error.
func TestSendRebootIdleAndInvalid(t *testing.T) {
	s := NewScanner()
	s.open = func() (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	if err := s.SendReboot("not-an-ip"); err == nil {
		t.Error("expected an error for an invalid device address")
	}
	if err := s.SendReboot("127.0.0.1"); err != nil {
		t.Errorf("idle SendReboot should open a one-shot socket and send: %v", err)
	}
}
