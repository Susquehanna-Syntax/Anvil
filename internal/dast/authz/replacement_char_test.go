package authz

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// replacementChar is U+FFFD, the REPLACEMENT CHARACTER, encoded as the three
// bytes EF BF BD.
//
// It is written as an ESCAPE and never as a literal, so that this file is not
// itself an instance of the thing it searches for — a scanner that matches its
// own source is a scanner that can only fail — and so that a reader can see
// what is being searched for instead of their editor rendering it as the same
// black diamond it renders every other occurrence as.
const replacementChar = "\uFFFD"

// TestNoReplacementCharactersInTheTree scans the source tree for U+FFFD.
//
// # WHY A UTF-8 VALIDITY SWEEP CANNOT DO THIS, WHICH IS THE WHOLE POINT
//
// A previous round reported "every .go and .md file decodes as valid UTF-8"
// and concluded from it that the tree was clean. That statement was TRUE and
// it was IRRELEVANT: EF BF BD — the encoding of U+FFFD — IS ITSELF VALID
// UTF-8. A validity sweep is structurally incapable of seeing this damage, so
// it returned a green result over four replacement characters sitting in
// production source where em-dashes belonged (phase4_disclosure.go, in the
// GateAudit doc comments). The check was not wrong about its own question; it
// was being used to answer a different one.
//
// So this scans for THE CODEPOINT, in the bytes, and for nothing else. The
// premise is asserted rather than assumed: the planted buffer below is checked
// to be valid UTF-8 AND to contain the character, in the same breath.
//
// # Why U+FFFD in a source file is worth a test at all
//
// Because it is the residue of a lossy decode and it is silent. Some editor or
// pipeline read a byte sequence it could not decode and substituted the
// replacement character; the file still compiles, still passes gofmt, still
// round-trips through every tool in this repository, and the original
// character is gone. In a comment it costs legibility. In a string literal
// that reaches an audit row or a refusal message it costs the exact text
// somebody will grep for later. There is no case in which one belongs in this
// tree on purpose, so there is no allowlist.
func TestNoReplacementCharactersInTheTree(t *testing.T) {
	// THE DETECTOR'S OWN CONTROL, first, so that a green result below cannot
	// mean "the matcher never matches".
	planted := []byte("an em dash was here: " + replacementChar + " and text after it")
	if !bytes.Contains(planted, []byte(replacementChar)) {
		t.Fatal("the detector does not find a planted U+FFFD, so the scan below proves " +
			"nothing")
	}
	if !utf8.Valid(planted) {
		t.Fatal("the planted buffer does not decode as valid UTF-8. If this ever fails " +
			"then the premise of this test is wrong and a validity sweep WOULD have " +
			"caught the damage")
	}

	root := repoRoot(t)
	scanned := 0
	sawTheKnownFile := false
	known := filepath.Join(root, "internal", "dast", "authz", "phase4_disclosure.go")

	for _, sub := range []string{"internal", ".github", "cmd", "test"} {
		dir := filepath.Join(root, sub)
		if _, err := os.Stat(dir); err != nil {
			// internal/ and .github/ are not optional: their absence means
			// this walk is not looking at this repository.
			if sub == "internal" || sub == ".github" {
				t.Fatalf("%s does not exist under %s, so this scan is not rooted in the "+
					"repository: %v", sub, root, err)
			}
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".go", ".md", ".yml", ".yaml":
			default:
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			if path == known {
				sawTheKnownFile = true
			}
			if i := bytes.Index(raw, []byte(replacementChar)); i >= 0 {
				rel, rerr := filepath.Rel(root, path)
				if rerr != nil {
					rel = path
				}
				line := 1 + bytes.Count(raw[:i], []byte("\n"))
				t.Errorf("%s:%d holds U+FFFD (EF BF BD) at byte offset %d. That is the "+
					"REPLACEMENT CHARACTER, the residue of a lossy decode — most often an "+
					"em-dash, a quotation mark or a non-breaking space some editor could "+
					"not decode. It is VALID UTF-8, so a UTF-8 validity sweep reports this "+
					"file clean; that is precisely why this test scans for the codepoint. "+
					"Put back the character that was lost.",
					filepath.ToSlash(rel), line, i)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}

	// The walk must not pass by having walked nothing.
	if scanned < 50 {
		t.Fatalf("the scan looked at %d files under %s. That is too few for this "+
			"repository, so the walk is rooted somewhere it should not be and a clean "+
			"result would mean nothing", scanned, root)
	}
	if !sawTheKnownFile {
		t.Fatalf("the scan did not reach %s, which is the file the four known "+
			"replacement characters were in. A survey that cannot reach the known case "+
			"is not a survey", known)
	}
	t.Logf("scanned %d .go/.md/.yml/.yaml files under %s", scanned, root)
}

// repoRoot walks up from the test's working directory until it finds go.mod.
//
// It FAILS rather than defaulting to anything: a guard that silently scans the
// wrong directory reports a clean tree it never looked at.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving the working directory: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.mod found walking up from the test's working directory, so this "+
		"scan cannot locate the repository root and refuses to scan an arbitrary "+
		"directory instead. Stopped at %s", dir)
	return ""
}
