package web

import (
	"reflect"
	"testing"
)

// TestSplitVendors proves the comma/space OUI splitter returns nil (not an empty
// slice) for empty/separator-only input - the contract the stored ScopeConfig relies
// on - and tokenizes a mixed list.
func TestSplitVendors(t *testing.T) {
	if got := splitVendors(""); got != nil {
		t.Errorf("splitVendors(\"\") = %#v, want nil", got)
	}
	if got := splitVendors("  ,  , "); got != nil {
		t.Errorf("separator-only -> %#v, want nil", got)
	}
	got := splitVendors("001f80, 00:1f:80 aabbcc")
	want := []string{"001f80", "00:1f:80", "aabbcc"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitVendors = %#v, want %#v", got, want)
	}
}
