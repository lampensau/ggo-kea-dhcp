package network

import (
	"strings"
	"testing"
)

// callContaining reports whether any recorded call contains all the given tokens.
func callContaining(rec *RecordingCommander, tokens ...string) bool {
	for _, call := range rec.Calls {
		joined := strings.Join(call, " ")
		all := true
		for _, tok := range tokens {
			if !strings.Contains(joined, tok) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func TestRebootAndPowerOffIssueSystemctl(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.Reboot(); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if err := m.PowerOff(); err != nil {
		t.Fatalf("PowerOff: %v", err)
	}
	if !callContaining(rec, "systemctl", "reboot") {
		t.Errorf("expected systemctl reboot; calls=%v", rec.Calls)
	}
	if !callContaining(rec, "systemctl", "poweroff") {
		t.Errorf("expected systemctl poweroff; calls=%v", rec.Calls)
	}
}

func TestSetInterfaceStaticIssuesNmcli(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.SetInterfaceStatic("eth0", "10.0.0.1/24"); err != nil {
		t.Fatalf("SetInterfaceStatic: %v", err)
	}
	if !callContaining(rec, "nmcli", "connection", "add", "ip4", "10.0.0.1/24") {
		t.Errorf("expected an nmcli connection add with the ip4; calls=%v", rec.Calls)
	}
	if !callContaining(rec, "nmcli", "connection", "up", "ggo-eth0") {
		t.Errorf("expected an nmcli connection up ggo-eth0; calls=%v", rec.Calls)
	}
}

func TestSetVlanStaticIssuesNmcliVlan(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.SetVlanStatic("eth0", 20, "10.20.0.1/24"); err != nil {
		t.Fatalf("SetVlanStatic: %v", err)
	}
	if !callContaining(rec, "nmcli", "connection", "add", "type", "vlan", "id", "20") {
		t.Errorf("expected an nmcli vlan add with id 20; calls=%v", rec.Calls)
	}
	if !callContaining(rec, "ggo-eth0.20") {
		t.Errorf("expected the ggo-eth0.20 connection name; calls=%v", rec.Calls)
	}
}

func TestApplyMasqueradeEnabledAddsRule(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.ApplyMasquerade("wlan0", true); err != nil {
		t.Fatalf("ApplyMasquerade: %v", err)
	}
	if !callContaining(rec, "nft", "flush", "chain", "ggo_nat", "postrouting") {
		t.Errorf("expected a flush before adding the rule; calls=%v", rec.Calls)
	}
	if !callContaining(rec, "nft", "add", "rule", "oifname", "wlan0", "masquerade") {
		t.Errorf("expected a masquerade rule on wlan0; calls=%v", rec.Calls)
	}
}

func TestApplyMasqueradeDisabledFlushesOnly(t *testing.T) {
	rec := &RecordingCommander{}
	m := NewManagerWithCommander(rec)
	if err := m.ApplyMasquerade("wlan0", false); err != nil {
		t.Fatalf("ApplyMasquerade(false): %v", err)
	}
	if !callContaining(rec, "nft", "flush", "chain", "ggo_nat", "postrouting") {
		t.Errorf("expected a flush; calls=%v", rec.Calls)
	}
	if callContaining(rec, "masquerade") {
		t.Errorf("disabled masquerade must not add a masquerade rule; calls=%v", rec.Calls)
	}
}

func TestCommanderErrorPropagates(t *testing.T) {
	rec := &RecordingCommander{Err: errDummy}
	m := NewManagerWithCommander(rec)
	if err := m.SetInterfaceStatic("eth0", "10.0.0.1/24"); err == nil {
		t.Error("expected SetInterfaceStatic to surface the commander error")
	}
}

var errDummy = &dummyErr{}

type dummyErr struct{}

func (*dummyErr) Error() string { return "boom" }

func TestParseIwScan(t *testing.T) {
	out := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
	signal: -50.00 dBm
	SSID: TestNet
	RSN:	 * Version: 1
BSS 11:22:33:44:55:66(on wlan0)
	signal: -80.00 dBm
	SSID: OpenNet
`
	aps := parseIwScan(out)
	if len(aps) != 2 {
		t.Fatalf("got %d APs want 2: %+v", len(aps), aps)
	}
	byName := map[string]WifiAP{}
	for _, ap := range aps {
		byName[ap.SSID] = ap
	}
	if got := byName["TestNet"]; got.Signal != 100 || got.Security != "WPA2/WPA3" {
		t.Errorf("TestNet parsed wrong: %+v", got)
	}
	if got := byName["OpenNet"]; got.Signal != 40 || got.Security != "Open" {
		t.Errorf("OpenNet parsed wrong: %+v", got)
	}
}

func TestParseIwlistScan(t *testing.T) {
	out := `          Cell 01 - Address: AA:BB:CC:DD:EE:FF
                    ESSID:"TestNet"
                    Signal level=-60 dBm
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 02 - Address: 11:22:33:44:55:66
                    ESSID:"OpenNet"
                    Signal level=-75 dBm
`
	aps := parseIwlistScan(out)
	if len(aps) != 2 {
		t.Fatalf("got %d APs want 2: %+v", len(aps), aps)
	}
	byName := map[string]WifiAP{}
	for _, ap := range aps {
		byName[ap.SSID] = ap
	}
	if got := byName["TestNet"]; got.Signal != 80 || got.Security != "WPA2/WPA3" {
		t.Errorf("TestNet parsed wrong: %+v", got)
	}
	if got := byName["OpenNet"]; got.Signal != 50 || got.Security != "Open" {
		t.Errorf("OpenNet parsed wrong: %+v", got)
	}
}

func TestParseNmcliScan(t *testing.T) {
	out := "TestNet:72:WPA2\nOpenNet:55:\nTestNet:30:WPA2\n" // duplicate TestNet ignored
	aps := parseNmcliScan(out, make(map[string]bool))
	if len(aps) != 2 {
		t.Fatalf("got %d APs want 2 (dedup): %+v", len(aps), aps)
	}
	if aps[0].SSID != "TestNet" || aps[0].Signal != 72 || aps[0].Security != "WPA2" {
		t.Errorf("TestNet parsed wrong: %+v", aps[0])
	}
}

// TestParseNmcliScanColonSSID is the integration check for the escaped-colon split
// (splitNmcliTerse's own edge cases are tabled in parse_test.go): an SSID containing
// a `\:`-escaped colon must parse as one AP, not mis-split into garbage fields.
func TestParseNmcliScanColonSSID(t *testing.T) {
	aps := parseNmcliScan(`My\:Net:72:WPA2`+"\n", make(map[string]bool))
	if len(aps) != 1 || aps[0].SSID != "My:Net" {
		t.Fatalf("got %+v want one AP SSID My:Net", aps)
	}
}
