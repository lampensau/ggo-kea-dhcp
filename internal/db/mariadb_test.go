package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// TestIsDuplicateKey covers the classifier the reconcile-time subnet remap uses to
// tell "target triple occupied - skip this row" from a real write failure.
func TestIsDuplicateKey(t *testing.T) {
	dup := &mysql.MySQLError{Number: 1062, Message: "Duplicate entry"}
	if !IsDuplicateKey(dup) {
		t.Error("1062 should classify as duplicate key")
	}
	if !IsDuplicateKey(fmt.Errorf("update hosts: %w", dup)) {
		t.Error("wrapped 1062 should classify as duplicate key")
	}
	if IsDuplicateKey(&mysql.MySQLError{Number: 1146, Message: "no such table"}) {
		t.Error("a non-1062 MySQL error is not a duplicate key")
	}
	if IsDuplicateKey(errors.New("plain error")) || IsDuplicateKey(nil) {
		t.Error("non-MySQL errors (and nil) are not duplicate keys")
	}
}
