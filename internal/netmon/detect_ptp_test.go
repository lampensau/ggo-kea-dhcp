package netmon

import (
	"strings"
	"testing"
	"time"
)

func TestPTP_GMPresenceAndLoss(t *testing.T) {
	d := newPTPDetector("eth0", 15*time.Second)

	// L2 Announce in domain 0 → GM present (info), snapshot ok.
	d.Consume(ptpAnnounce(0, 0xaabbccddeeff0011, 128, 128, false), at(1*time.Second))
	ev := d.Tick(at(1 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevInfo {
		t.Fatalf("expected one info GM-seen event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevOK {
		t.Fatalf("snapshot with one GM = %+v", s)
	}

	// GM goes silent past absence → last GM gone → warn (sync lost).
	ev = d.Tick(at(30 * time.Second))
	if len(ev) != 1 || ev[0].Severity != SevWarn {
		t.Fatalf("expected one warn GM-lost event, got %v", ev)
	}
	if s := d.Snapshot(); s.Severity != SevWarn {
		t.Fatalf("snapshot after GM loss = %+v", s)
	}
}

func TestPTP_MultipleGMsIsInfo(t *testing.T) {
	d := newPTPDetector("eth0", 15*time.Second)
	d.Consume(ptpAnnounce(0, 0x1111111111111111, 128, 128, true), at(1*time.Second))
	d.Consume(ptpAnnounce(0, 0x2222222222222222, 129, 128, true), at(1*time.Second))
	d.Tick(at(1 * time.Second))
	s := d.Snapshot()
	if s.Severity != SevInfo {
		t.Fatalf("two GMs should be info (BMCA failover), got %+v", s)
	}
}

// TestPTP_ConcurrentBackupsAreInfo guards the churn fix: three GMs present at
// once (a normal BMCA backup stack) must read as info, NOT churn - concurrent
// breadth is not turnover.
func TestPTP_ConcurrentBackupsAreInfo(t *testing.T) {
	d := newPTPDetector("eth0", 15*time.Second)
	d.Consume(ptpAnnounce(0, 0x1, 128, 128, false), at(1*time.Second))
	d.Consume(ptpAnnounce(0, 0x2, 129, 128, false), at(1*time.Second))
	d.Consume(ptpAnnounce(0, 0x3, 130, 128, false), at(1*time.Second))
	d.Tick(at(1 * time.Second))
	if s := d.Snapshot(); s.Severity != SevInfo {
		t.Fatalf("three concurrent backup GMs should be info, got %+v", s)
	}
}

// TestPTP_ChurnWarns: churn is GM turnover over time. Three short-lived GMs each
// appear then drop within the window (3 losses) while a stable GM is present at
// the end - so the state is "contention" (warn), not merely "lost".
func TestPTP_ChurnWarns(t *testing.T) {
	d := newPTPDetector("eth0", 15*time.Second)
	flap := func(id uint64, appear, lose time.Duration) {
		d.Consume(ptpAnnounce(0, id, 128, 128, false), at(appear))
		d.Tick(at(appear))
		d.Tick(at(lose)) // no further announce → lost after the absence window
	}
	flap(0x1, 1*time.Second, 20*time.Second)
	flap(0x2, 21*time.Second, 40*time.Second)
	flap(0x3, 41*time.Second, 60*time.Second)
	// A stable GM remains, so the domain isn't merely "empty/lost".
	d.Consume(ptpAnnounce(0, 0x4, 128, 128, false), at(61*time.Second))
	d.Tick(at(61 * time.Second))

	s := d.Snapshot()
	if s.Severity != SevWarn {
		t.Fatalf("repeated GM turnover should warn, got %+v", s)
	}
	if !strings.Contains(s.Text, "contention") {
		t.Fatalf("expected churn 'contention' text, got %q", s.Text)
	}
}
