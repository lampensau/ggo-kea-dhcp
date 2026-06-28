package preflight

import "testing"

func TestResultHasFailure(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want bool
	}{
		{"empty", Result{}, false},
		{"all ok", Result{{Status: OK}, {Status: OK}}, false},
		{"warn only", Result{{Status: OK}, {Status: Warn}}, false},
		{"one fail", Result{{Status: OK}, {Status: Fail}, {Status: Warn}}, true},
	}
	for _, c := range cases {
		if got := c.r.HasFailure(); got != c.want {
			t.Errorf("%s: HasFailure()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestResultWorst(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want Status
	}{
		{"empty -> OK", Result{}, OK},
		{"all ok", Result{{Status: OK}}, OK},
		{"warn beats ok", Result{{Status: OK}, {Status: Warn}}, Warn},
		{"fail beats warn", Result{{Status: Warn}, {Status: Fail}, {Status: OK}}, Fail},
	}
	for _, c := range cases {
		if got := c.r.Worst(); got != c.want {
			t.Errorf("%s: Worst()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestCapCheck(t *testing.T) {
	// bit 13 (CAP_NET_RAW) held -> OK; absent -> Warn.
	const bit = 13
	held := capCheck("x", uint64(1)<<bit, bit)
	if held.Status != OK {
		t.Errorf("held cap: status=%v want OK", held.Status)
	}
	absent := capCheck("x", 0, bit)
	if absent.Status != Warn {
		t.Errorf("absent cap: status=%v want Warn", absent.Status)
	}
	// A different bit set must not be mistaken for this one (catches & vs |).
	other := capCheck("x", uint64(1)<<(bit+1), bit)
	if other.Status != Warn {
		t.Errorf("wrong bit set: status=%v want Warn", other.Status)
	}
}
