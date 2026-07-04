package web

import (
	"testing"
	"time"
)

func TestClockStepDesc(t *testing.T) {
	cases := []struct {
		step    time.Duration
		wantDir string
		wantMag time.Duration
	}{
		{5 * time.Hour, "forward", 5 * time.Hour},
		{-3 * time.Minute, "backward", 3 * time.Minute},
		{0, "forward", 0},
		{-24 * time.Hour, "backward", 24 * time.Hour},
	}
	for _, c := range cases {
		dir, mag := clockStepDesc(c.step)
		if dir != c.wantDir || mag != c.wantMag {
			t.Errorf("clockStepDesc(%v)=(%q,%v) want (%q,%v)", c.step, dir, mag, c.wantDir, c.wantMag)
		}
	}
}
