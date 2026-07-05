package web

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTailLines(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want []string
	}{
		{"", 3, nil},
		{"a\nb\nc\n", 5, []string{"a", "b", "c"}},
		{"a\nb\nc\nd", 2, []string{"c", "d"}},
		{"only\n\n", 3, []string{"only"}}, // trailing blank lines collapse
	} {
		if got := tailLines(tc.in, tc.n); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("tailLines(%q, %d) = %#v, want %#v", tc.in, tc.n, got, tc.want)
		}
	}
}

// The apt.log tail must appear only when the staged file exists and must be
// capped to the render limit.
func TestAptLogTail(t *testing.T) {
	s, _ := newTestServer(t)
	s.updateDir = t.TempDir()

	if got := s.aptLogTail(); got != nil {
		t.Errorf("no apt.log on disk but tail = %#v", got)
	}

	content := ""
	for i := 0; i < logTailLines+10; i++ {
		content += "line\n"
	}
	if err := os.WriteFile(filepath.Join(s.updateDir, updateAptLogFile), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	got := s.aptLogTail()
	if len(got) != logTailLines {
		t.Errorf("apt.log tail = %d lines, want capped at %d", len(got), logTailLines)
	}
}

// One over-long burst must not bloat the page: the byte cap keeps the newest
// bytes and drops the truncated first line.
func TestTailLinesByteCap(t *testing.T) {
	long := strings.Repeat("x", logTailBytes) + "\ntail-line\n"
	got := tailLines(long, 5)
	for _, l := range got {
		if len(l) > logTailBytes {
			t.Fatalf("line survived over the byte cap (%d bytes)", len(l))
		}
	}
	if len(got) == 0 || got[len(got)-1] != "tail-line" {
		t.Errorf("newest line lost under the byte cap: %v", got)
	}
}
