//go:build ignore

// Command stripcomments reads Go source on stdin and writes it back with every
// comment gone, so assert-comment-only.sh can diff two revisions of a file for
// code equality. Parsing without parser.ParseComments leaves the comments
// unattached to the AST, so go/printer never emits them.
//
// go/printer reproduces the source's line structure from token positions, and
// deleting a comment shifts every position after it. Printing against a FileSet that
// never saw those positions yields canonical output instead, so the comparison cannot
// mistake a moved line for a changed one. Blank lines are dropped here rather than by
// a downstream `awk NF`, so the caller can invoke this as a simple command and let
// `set -e` see a parse error or a broken toolchain.
package main

import (
	"bytes"
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"strings"
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
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), f); err != nil {
		fail(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.TrimSpace(line) != "" {
			fmt.Println(line)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "stripcomments:", err)
	os.Exit(1)
}
