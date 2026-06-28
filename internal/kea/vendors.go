package kea

import (
	"strconv"
	"strings"
)

// NormalizeOUI lowercases a MAC-address prefix and strips separators, returning ""
// unless it's a valid 6–12 hex-digit prefix. Lengths longer than 6 match an IEEE
// sub-block: MA-L is 6 hex (24-bit), MA-M is 7 (28-bit), MA-S is 9 (36-bit). Using
// the full assigned prefix (e.g. 0055da4, 70b3d5ee8) is what makes a vendor in a
// SHARED parent block (0050c2, 70b3d5, …) match precisely instead of over-catching.
func NormalizeOUI(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	o := b.String()
	if len(o) < 6 || len(o) > 12 {
		return ""
	}
	return o
}

// NormalizeOUI6 returns the FIRST 6 hex digits (the standard 3-byte OUI) of a typed
// MAC/prefix, or "" if fewer than 6 are present. Operator-typed custom OUIs are
// restricted to this simple 3-byte form - entering a precise 7/9-hex sub-block is
// error-prone, so only OUR curated table uses the longer prefixes.
func NormalizeOUI6(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
			if b.Len() == 6 {
				break
			}
		}
	}
	if b.Len() < 6 {
		return ""
	}
	return b.String()
}

// maxOUILen is the length of a pool's longest (most specific) OUI prefix - its
// match specificity for pool ordering (longest-prefix-wins).
func maxOUILen(ouis []string) int {
	m := 0
	for _, o := range ouis {
		if n := NormalizeOUI(o); len(n) > m {
			m = len(n)
		}
	}
	return m
}

// VendorClassTest builds the Kea client-class `test` expression matching a device
// whose MAC begins with any of the given prefixes (OR-matched). The match length
// follows each prefix's length, so a 7- or 9-hex sub-block prefix matches exactly
// that assignment. Invalid prefixes are skipped; returns "" when none are valid.
func VendorClassTest(ouis []string) string {
	var terms []string
	for _, o := range ouis {
		if n := NormalizeOUI(o); n != "" {
			terms = append(terms, "substring(hexstring(pkt4.mac, ''), 0, "+strconv.Itoa(len(n))+") == '"+n+"'")
		}
	}
	switch len(terms) {
	case 0:
		return ""
	case 1:
		return terms[0]
	default:
		return "(" + strings.Join(terms, " or ") + ")"
	}
}
