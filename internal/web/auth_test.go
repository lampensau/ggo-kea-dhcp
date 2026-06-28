package web

import (
	"strings"
	"testing"
)

func TestHashPasswordVerifyRoundTrip(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "pbkdf2$600000$") {
		t.Errorf("unexpected hash format: %q", hash)
	}
	if !verifyPassword(hash, "correct horse battery staple") {
		t.Error("verifyPassword rejected the correct password")
	}
	if verifyPassword(hash, "wrong password") {
		t.Error("verifyPassword accepted a wrong password")
	}
}

func TestHashPasswordSaltsDiffer(t *testing.T) {
	a, _ := hashPassword("same")
	b, _ := hashPassword("same")
	if a == b {
		t.Error("two hashes of the same password collided (salt not random)")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, stored := range []string{
		"",
		"plaintext",
		"pbkdf2$notanint$aa$bb",
		"bcrypt$10$salt$hash",      // non-pbkdf2 scheme: hard cutover
		"pbkdf2$600000$nothex$bb",  // bad salt hex
		"pbkdf2$600000$aa$nothex2", // bad hash hex
	} {
		if verifyPassword(stored, "anything") {
			t.Errorf("verifyPassword accepted malformed stored hash %q", stored)
		}
	}
}
