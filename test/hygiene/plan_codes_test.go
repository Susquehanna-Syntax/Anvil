// Package hygiene_test holds repository-wide guards: checks about the tree as
// a whole rather than about any one package.
package hygiene_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The first plan named work by code: an area letter and a step number, an
// experiment number, a numbered review file. Source comments, review files,
// test names and CI jobs grew up citing those codes, and a code only resolves
// with the plan open. The plan is not distributed (plan/ is gitignored), so
// every citation was a pointer into a document the reader does not have. They
// were rewritten into words; TestNoPlanCodesInTheTree keeps them from coming
// back.
//
// Only shapes that cannot mean anything else are refused. Spine section
// numbers and ruling numbers are deliberately absent: the same shapes are
// research source citations ("research/01 S5") and a component's own guard
// labels, so a pattern for them would refuse legitimate text. Those were
// rewritten by hand and are held by review, not by this test.
var refused = []struct {
	what string
	re   *regexp.Regexp
}{
	{"a plan step code", regexp.MustCompile(`\b(?:M0\.[0-9]{1,2}|[ABCDORX]\.[0-9]{1,2})\b`)},
	{"an old experiment-register ID", regexp.MustCompile(`\b(?:EXP|INSTR)-[0-9]{2}\b`)},
	{"an old review-file name", regexp.MustCompile(`\bCRITIQUE-?[0-9]{2}\b`)},
	{"a first-plan file name", regexp.MustCompile(`\b(?:00-SPINE|00-ROUTING|IMPLEMENTATION-PLAN|` +
		`HANDOFF-PROMPT|SPINE-S4-RECALL-TIER|10-milestone0-evaluation|20-lane-a-ingestion-sca|` +
		`30-lane-b-detection|40-record-and-storage|50-dast|60-remediation|70-orchestration-ci|` +
		`80-compliance)\b`)},
}

// thisFile is excluded from the scan because it has to spell the shapes it
// refuses.
const thisFile = "test/hygiene/plan_codes_test.go"

// skipDirs is the fallback walk's copy of what .gitignore keeps out of the
// repository. It is used only when git cannot list the tree.
var skipDirs = map[string]bool{
	".git": true, "plan": true, "research": true, "tools": true, ".venv": true, "venv": true,
	"node_modules": true, "dist": true, "build": true, "__pycache__": true, ".pytest_cache": true,
	".ruff_cache": true, ".cache": true, ".anvil": true, "buffer": true, "models": true, "vendor": true,
}

func TestNoPlanCodesInTheTree(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || !bytes.Contains(mod, []byte("module github.com/Susquehanna-Syntax/Anvil")) {
		t.Fatalf("%s is not the Anvil module root (go.mod: %v); the scan would cover the wrong tree", root, err)
	}

	files, how := listTree(t, root)
	t.Logf("scanning %d files (%s)", len(files), how)
	// A listing that came back nearly empty would pass every file it did not
	// see. The repository has hundreds of files; a few dozen means the listing
	// broke, not that the tree shrank.
	if len(files) < 150 {
		t.Fatalf("the listing returned %d files (%s); that is a broken listing, not a clean tree", len(files), how)
	}

	for _, rel := range files {
		if rel == thisFile {
			continue
		}
		for _, r := range refused {
			if loc := r.re.FindString(rel); loc != "" {
				t.Errorf("%s: the path carries %s (%q); name the file after what it covers", rel, r.what, loc)
			}
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // listed by git but deleted in the working tree
			}
			t.Fatal(err)
		}
		head := data
		if len(head) > 8000 {
			head = head[:8000]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			continue // binary
		}
		for n, line := range strings.Split(string(data), "\n") {
			for _, r := range refused {
				if loc := r.re.FindString(line); loc != "" {
					t.Errorf("%s:%d cites %s (%q). Say what it means in words, and cite a plan node by "+
						"name if a pointer helps:\n    %s", rel, n+1, r.what, loc, strings.TrimSpace(line))
				}
			}
		}
	}
}

// listTree returns the files the repository distributes, slash-separated and
// relative to root: git's own listing (tracked plus untracked-but-not-ignored)
// when git is available, otherwise a walk that skips the ignored directories.
func listTree(t *testing.T, root string) ([]string, string) {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = root
	if out, err := cmd.Output(); err == nil {
		var files []string
		for _, f := range strings.Split(string(out), "\x00") {
			if f != "" {
				files = append(files, f)
			}
		}
		return files, "git ls-files"
	}
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files, "walk without git"
}

// TestThePatternsRefuseTheOldShapesAndNothingElse is the negative control: a
// guard nobody has seen fail is not known to work. Each refused example is a
// shape the rewrite removed; each allowed example is a shape that stays and
// that a careless pattern would catch.
func TestThePatternsRefuseTheOldShapesAndNothingElse(t *testing.T) {
	refusedExamples := []string{
		"see A.17 and A.18",
		"the gate decision (M0.18)",
		"owned by D.9's write scope",
		"R.1 froze the enums",
		"X.20 composes the PR body",
		"EXP-04 measured nothing",
		"INSTR-01 counts candidates",
		"internal/record/CRITIQUE-03.md",
		"plan/40-record-and-storage.md",
		"plan/IMPLEMENTATION-PLAN.md",
	}
	allowedExamples := []string{
		"research/01 S5 is the NVD terms page",
		"RFC 9110 §15.4.4",
		"opengrep v1.26.0",
		"gates 4, 5, 8, 9 and 10",
		"Phase 4: close the confirmation gate",
		"the read-only-boundary review's finding M1(a)",
		"U7 is recorded in docs/controls.md",
		"SARIF 2.1.0 §3.27.4",
		"research/10-prior-art-and-landscape.md",
		"the confirmation gate's rules R1, R2 and R3",
		"ULID 01J8.3",
	}
	matches := func(s string) bool {
		for _, r := range refused {
			if r.re.MatchString(s) {
				return true
			}
		}
		return false
	}
	for _, s := range refusedExamples {
		if !matches(s) {
			t.Errorf("not refused, and it is one of the shapes the rewrite removed: %q", s)
		}
	}
	for _, s := range allowedExamples {
		if matches(s) {
			t.Errorf("refused, and it is legitimate text that stays: %q", s)
		}
	}
}
