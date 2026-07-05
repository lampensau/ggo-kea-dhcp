package web

import (
	"fmt"
	"strings"
	"testing"
	"time"
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
		"pbkdf2$0$aa$" + strings.Repeat("00", 32),      // zero iterations
		"pbkdf2$-1$aa$" + strings.Repeat("00", 32),     // negative iterations
		"pbkdf2$600000$aa$" + strings.Repeat("00", 16), // hash too short
		"pbkdf2$600000$aa$" + strings.Repeat("00", 64), // hash too long
	} {
		if verifyPassword(stored, "anything") {
			t.Errorf("verifyPassword accepted malformed stored hash %q", stored)
		}
	}
}

// A stored hash must not be able to dictate unbounded key-derivation work: a
// crafted iteration count or an oversized hash field (dkLen multiplies PBKDF2
// cost too) has to fail fast instead of hanging the login handler.
func TestVerifyPasswordBoundsWork(t *testing.T) {
	salt := strings.Repeat("00", 16)
	for name, stored := range map[string]string{
		"huge iteration count": fmt.Sprintf("pbkdf2$50000000000$%s$%s", salt, strings.Repeat("00", 32)),
		"oversized hash field": fmt.Sprintf("pbkdf2$600000$%s$%s", salt, strings.Repeat("00", 1<<20)),
	} {
		done := make(chan bool, 1)
		go func() { done <- verifyPassword(stored, "anything") }()
		select {
		case ok := <-done:
			if ok {
				t.Errorf("%s: verifyPassword accepted the hash", name)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s: verifyPassword did not return within 3s", name)
		}
	}
}
