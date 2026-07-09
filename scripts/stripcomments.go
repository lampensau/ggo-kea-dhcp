//go:build ignore

// Command stripcomments reads Go source on stdin and writes it back with every
// comment gone, so assert-comment-only.sh can diff two revisions of a file for
// code equality. Parsing without parser.ParseComments leaves the comments
// unattached to the AST, so go/printer never emits them.
//
// go/printer reproduces the source's line structure from token positions, and
// deleting a comment shifts every position after it. Printing against a FileSet that
// never saw those positions yields canonical output instead, so the comparison cannot
// mistake a moved line for a changed one.
package main

import (
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
)

func main() {
	src, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "src.go", src, 0)
	if err != nil {
		fail(err)
	}
	// A fresh FileSet: printing against the parse positions would re-inject the
	// blank-line structure the comments left behind.
	if err := printer.Fprint(os.Stdout, token.NewFileSet(), f); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "stripcomments:", err)
	os.Exit(1)
}
