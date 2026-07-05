package views

import (
	"context"
	"strings"
	"testing"
)

// Release notes are remote content (the GitHub release body) rendered into the
// operator's page - a trust boundary. The renderer must emit them as escaped
// text only, never as markup.
func TestReleaseNotesDialogEscapesHostileBody(t *testing.T) {
	hostile := "## <script>alert(1)</script>\r\n" +
		"- <img src=x onerror=alert(2)>\r\n" +
		"para with <b>markup</b> & \"quotes\"\r\n" +
		"* second </dialog><script>alert(3)</script>"
	var b strings.Builder
	if err := ReleaseNotesDialog(UpdateView{Version: "9.9.9", Notes: hostile}).Render(context.Background(), &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	// The escaped text still CONTAINS the attack strings as inert text (that is the
	// point) - what must never appear is an unescaped tag opener.
	for _, bad := range []string{"<script>", "<img", "<b>markup"} {
		if strings.Contains(out, bad) {
			t.Errorf("hostile markup reached the DOM: %q", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "&lt;img"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected escaped form %q in output", want)
		}
	}
	// The </dialog> in the body must not terminate the dialog element early.
	if strings.Count(out, "</dialog>") != 1 {
		t.Errorf("body content broke out of the dialog element")
	}
}

func TestParseReleaseNotesBlocks(t *testing.T) {
	blocks := parseReleaseNotes("## Heading\r\n\r\n- a\n- b\n\npara one\npara two\n* c")
	kinds := make([]string, 0, len(blocks))
	for _, b := range blocks {
		kinds = append(kinds, b.Kind)
	}
	want := []string{"h", "list", "p", "p", "list"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	if blocks[0].Text != "Heading" {
		t.Errorf("heading text = %q", blocks[0].Text)
	}
	if len(blocks[1].Items) != 2 || blocks[1].Items[1] != "b" {
		t.Errorf("list items = %v", blocks[1].Items)
	}
}

func TestUpdateBadgeRendersEmptyWhenHidden(t *testing.T) {
	var b strings.Builder
	if err := UpdateBadge(UpdateBadgeView{}).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "update-badge\"><a") || strings.Contains(b.String(), "href") {
		t.Fatalf("hidden badge must render an empty span: %s", b.String())
	}
	b.Reset()
	if err := UpdateBadge(UpdateBadgeView{Show: true, Version: "1.2.3"}).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "/settings#update") || !strings.Contains(b.String(), "1.2.3") {
		t.Fatalf("visible badge missing link/version: %s", b.String())
	}
}
