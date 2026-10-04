package remediation

import (
	"errors"
	"strings"
	"testing"
)

func edit(path, search, replace string) string {
	return "FILE: " + path + "\n<<<<<<< SEARCH\n" + search + "\n=======\n" + replace + "\n>>>>>>> REPLACE\n"
}

func TestAnEditAnchorsExactlyOnce(t *testing.T) {
	base := map[string]string{"a.c": "int x;\nstrcpy(buf, src);\nint y;\n"}
	got, err := Anchor(base, ParseEdits("Here you go:\n"+edit("a.c", "strcpy(buf, src);", "snprintf(buf, sizeof buf, \"%s\", src);")))
	if err != nil {
		t.Fatal(err)
	}
	if got["a.c"] != "int x;\nsnprintf(buf, sizeof buf, \"%s\", src);\nint y;\n" {
		t.Fatalf("%q", got["a.c"])
	}

	twice := map[string]string{"a.c": "f();\nf();\n"}
	_, err = Anchor(twice, ParseEdits(edit("a.c", "f();", "g();")))
	var an *ErrAnchor
	if !errors.As(err, &an) || !strings.Contains(an.Problems[0], "occurs 2 times") {
		t.Fatalf("a SEARCH that occurs twice was placed: %v", err)
	}
	_, err = Anchor(base, ParseEdits(edit("a.c", "not there", "x")))
	if !errors.As(err, &an) || !strings.Contains(an.Problems[0], "does not occur") {
		t.Fatalf("a SEARCH that does not occur was placed: %v", err)
	}
	_, err = Anchor(base, ParseEdits(edit("other.c", "int x;", "int z;")))
	if !errors.As(err, &an) || !strings.Contains(an.Problems[0], "not a file you may edit") {
		t.Fatalf("an edit to a file outside the group was placed: %v", err)
	}
	_, err = Anchor(base, ParseEdits("I think the code is fine."))
	if !errors.As(err, &an) {
		t.Fatalf("a reply with no edit block anchored: %v", err)
	}
	_, err = Anchor(base, ParseEdits(edit("a.c", "int x;", "int x;")))
	if !errors.As(err, &an) || !strings.Contains(an.Problems[0], "change nothing") {
		t.Fatalf("a no-op edit was accepted: %v", err)
	}
}

// TestCRLFAndTabIndentedFilesAnchor: the model answers in LF, a CRLF file keeps
// its line endings, and tab indentation is matched exactly, never normalised.
func TestCRLFAndTabIndentedFilesAnchor(t *testing.T) {
	crlf := map[string]string{"w.c": "void f() {\r\n\tstrcpy(b, s);\r\n\treturn;\r\n}\r\n"}
	got, err := Anchor(crlf, ParseEdits(edit("w.c", "\tstrcpy(b, s);\n\treturn;", "\tstrlcpy(b, s, sizeof b);\n\treturn;")))
	if err != nil {
		t.Fatal(err)
	}
	if got["w.c"] != "void f() {\r\n\tstrlcpy(b, s, sizeof b);\r\n\treturn;\r\n}\r\n" {
		t.Fatalf("%q", got["w.c"])
	}
	// The same SEARCH with spaces for the tab does not anchor: whitespace is
	// matched exactly.
	if _, err := Anchor(crlf, ParseEdits(edit("w.c", "    strcpy(b, s);", "x"))); err == nil {
		t.Fatal("a space-indented SEARCH anchored in a tab-indented file")
	}
	// A reply that itself arrives with CRLF line breaks parses.
	reply := strings.ReplaceAll(edit("w.c", "\tstrcpy(b, s);", "\tstrlcpy(b, s, sizeof b);"), "\n", "\r\n")
	if _, err := Anchor(crlf, ParseEdits(reply)); err != nil {
		t.Fatalf("a CRLF reply did not anchor: %v", err)
	}
}

func TestAWholeFileRewriteOnlyUnderTheLimit(t *testing.T) {
	small := map[string]string{"s.py": "a = 1\n"}
	reply := "FILE: s.py\n<<<<<<< WHOLE\na = 2\n>>>>>>> WHOLE\n"
	got, err := Anchor(small, ParseEdits(reply))
	if err != nil || got["s.py"] != "a = 2\n" {
		t.Fatalf("%q %v", got["s.py"], err)
	}
	big := map[string]string{"s.py": strings.Repeat("a = 1\n", WholeFileLimit)}
	if _, err := Anchor(big, ParseEdits(reply)); err == nil {
		t.Fatalf("a %d-line file was replaced whole", WholeFileLimit)
	}
}

func TestEditsKeepReplyOrder(t *testing.T) {
	reply := edit("a", "1", "2") + "FILE: b\n<<<<<<< WHOLE\nz\n>>>>>>> WHOLE\n" + edit("a", "3", "4")
	es := ParseEdits(reply)
	if len(es) != 3 || es[0].Search != "1" || !es[1].Whole || es[2].Search != "3" {
		t.Fatalf("%+v", es)
	}
}

// TestAPathGitWouldQuoteIsNeverPatched: a path with a tab, a newline, a quote,
// a backslash, a non-ASCII character or a dot segment is refused before any
// diff header is written for it.
func TestAPathGitWouldQuoteIsNeverPatched(t *testing.T) {
	for _, p := range []string{"a\tb.c", "a\nb.c", `a"b.c`, `a\b.c`, "é.c", "a b.c", "../x.c", "a//b.c", "./a.c", "-a.c", "/etc/x.c", ""} {
		if SafePath(p) == nil {
			t.Errorf("%q was accepted", p)
		}
		if disallowedPath(p) == "" {
			t.Errorf("the path rung accepted %q", p)
		}
	}
	for _, p := range []string{"src/a.c", "pkg/x_y-z.go", "A.Java"} {
		if err := SafePath(p); err != nil {
			t.Errorf("%q was refused: %v", p, err)
		}
	}
}
