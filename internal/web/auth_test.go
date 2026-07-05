package web

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
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
	salt := strings.Repeat("00", pbkdf2SaltLen) // valid-length salt, so each row fails on ITS property
	for _, stored := range []string{
		"",
		"plaintext",
		"pbkdf2$notanint$" + salt + "$bb",
		"bcrypt$10$salt$hash", // non-pbkdf2 scheme: hard cutover
		"pbkdf2$600000$" + strings.Repeat("nothex!!", 4) + "$" + strings.Repeat("00", 32), // bad salt hex
		"pbkdf2$600000$" + salt + "$" + strings.Repeat("nothex!!", 8),                     // bad hash hex
		"pbkdf2$0$" + salt + "$" + strings.Repeat("00", 32),                               // zero iterations
		"pbkdf2$-1$" + salt + "$" + strings.Repeat("00", 32),                              // negative iterations
		"pbkdf2$600000$" + salt + "$" + strings.Repeat("00", 16),                          // hash too short
		"pbkdf2$600000$" + salt + "$" + strings.Repeat("00", 64),                          // hash too long
		"pbkdf2$600000$" + strings.Repeat("00", 8) + "$" + strings.Repeat("00", 32),       // salt too short
		"pbkdf2$600000$" + strings.Repeat("00", 32) + "$" + strings.Repeat("00", 32),      // salt too long
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
		"oversized salt field": fmt.Sprintf("pbkdf2$600000$%s$%s", strings.Repeat("00", 1<<20), strings.Repeat("00", 32)),
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

// TestVerifyPasswordClampBoundary pins the iteration-clamp policy edge: a hash
// at exactly pbkdf2Iter*4 must verify (the headroom exists so a future
// higher-iteration build's backup still restores onto this binary), one past it
// must not. Both digests are genuinely derived, so the boundary - not a digest
// mismatch - is what each assertion proves. The accept side costs one real
// 2.4M-iteration derivation (~1s): the price of pinning policy, not
// implementation.
func TestVerifyPasswordClampBoundary(t *testing.T) {
	const pw = "boundary probe"
	salt := bytes.Repeat([]byte{0xa5}, pbkdf2SaltLen)
	mk := func(iter int) string {
		dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, sha256.Size)
		if err != nil {
			t.Fatalf("derive at %d iterations: %v", iter, err)
		}
		return fmt.Sprintf("pbkdf2$%d$%x$%x", iter, salt, dk)
	}
	if !verifyPassword(mk(pbkdf2Iter*4), pw) {
		t.Error("a hash at the clamp ceiling (pbkdf2Iter*4) must verify")
	}
	if verifyPassword(mk(pbkdf2Iter*4+1), pw) {
		t.Error("a hash one past the clamp ceiling must be rejected")
	}
}
