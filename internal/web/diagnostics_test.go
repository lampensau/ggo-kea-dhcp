package web

import (
	"os"
	"path/filepath"
	"reflect"
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
